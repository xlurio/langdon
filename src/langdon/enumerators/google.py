import abc
from collections.abc import Iterator
import tempfile
import time
from typing import cast
import requests
from selenium.webdriver.firefox import webdriver
from selenium.webdriver.firefox import options
from selenium.webdriver.support import wait, expected_conditions as ec
from sqlalchemy.orm import Session
from selenium.webdriver.common.by import By
from sqlalchemy import sql, exc
import pydub
from langdon import throttler
from langdon.exceptions import LangdonException
from langdon.models import Directory, LangdonConfig
import speech_recognition as sr

BASE_URL = "https://google.com"
THROTTLING_QUEUE = "throttler_google"


class GoogleRecognizerType(sr.Recognizer):
    @abc.abstractmethod
    def recognize_google(
        self, audio_data, key=None, language="en-US", show_all=False
    ) -> str:
        raise NotImplementedError


def _make_webdriver(*, session: Session) -> webdriver.WebDriver:
    firefox_profile_query = (
        sql.select(LangdonConfig.value)
        .where(LangdonConfig.name == "FIREFOX_PROFILE_PATH")
        .limit(1)
    )
    try:
        firefox_profile_path = session.execute(firefox_profile_query).scalar_one()
    except exc.NoResultFound as exception:
        raise LangdonException(
            "Please, configure your FIREFOX_PROFILE_PATH setting with `langdon config "
            "set FIREFOX_PROFILE_PATH /path/to/firefox/profile`"
        ) from exception

    wd_options = options.Options()
    # wd_options.add_argument("--headless")
    wd_options.set_preference("profile", firefox_profile_path)
    wd_options.set_preference("network.proxy.type", 1)
    wd_options.set_preference("network.proxy.socks", "localhost")
    wd_options.set_preference("network.proxy.socks_port", 9050)
    wd_options.set_preference(
        "general.useragent.override",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
    )

    return webdriver.WebDriver(options=wd_options)


def _solve_captcha(driver: webdriver.WebDriver) -> None:
    try:
        current_url = driver.current_url
        recaptcha_iframe = wait.WebDriverWait(driver, 60).until(
            ec.element_to_be_clickable((By.XPATH, "//iframe[@title='reCAPTCHA']"))
        )
        driver.switch_to.frame(recaptcha_iframe)
        wait.WebDriverWait(driver, 60).until(
            ec.element_to_be_clickable((By.ID, "recaptcha-anchor"))
        ).click()
        driver.switch_to.default_content()
        challenge_iframe = wait.WebDriverWait(driver, 60).until(
            ec.element_to_be_clickable(
                (
                    By.XPATH,
                    "//iframe[@title='recaptcha challenge expires in two minutes']",
                )
            )
        )
        driver.switch_to.frame(challenge_iframe)
        driver.find_element(By.ID, "recaptcha-audio-button").click()
        audio_src = (
            wait.WebDriverWait(driver, 60)
            .until(ec.presence_of_element_located((By.ID, "audio-source")))
            .get_attribute("src")
        )

        with tempfile.NamedTemporaryFile("w+b", suffix=".wav") as wav_file:
            with tempfile.NamedTemporaryFile("w+b", suffix=".mp3") as mp3_file:
                throttler.wait_for_slot(THROTTLING_QUEUE)
                mp3_file.write(requests.get(audio_src).content)
                audio_segment = cast(
                    "pydub.AudioSegment", pydub.AudioSegment.from_mp3(mp3_file.name)
                )

            audio_segment.export(wav_file.name, format="wav")
            recognizer = sr.Recognizer()

            with sr.AudioFile(wav_file.name) as source:
                audio = recognizer.record(source)

            challenge_response = (
                cast("GoogleRecognizerType", recognizer).recognize_google(audio).lower()
            )
            wait.WebDriverWait(driver, 60).until(
                ec.presence_of_element_located((By.ID, "audio-response"))
            ).send_keys(challenge_response)
            throttler.wait_for_slot(THROTTLING_QUEUE)
            wait.WebDriverWait(driver, 60).until(
                ec.element_to_be_clickable((By.ID, "recaptcha-verify-button"))
            ).click()
            wait.WebDriverWait(driver, 60).until(ec.url_changes(current_url))
    except wait.TimeoutException:
        raise LangdonException("Could not solve the captcha")


def enumerate_directories(domain: str, *, session: Session) -> Iterator[Directory]:
    with _make_webdriver(session=session) as driver:
        throttler.wait_for_slot(THROTTLING_QUEUE)
        driver.get(f"https://google.com/search?q=site:{domain}")
        time.sleep(5)

        if driver.current_url.startswith("https://www.google.com/sorry"):
            _solve_captcha(driver)

        while True:
            current_url = driver.current_url

            for element in driver.find_elements(By.XPATH, "//h3"):
                result_url = element.find_element(By.XPATH, "..").get_attribute("href")

                if (result_url is None) or (
                    ("*" not in domain) and (domain not in result_url)
                ):
                    continue

                yield Directory(url=result_url, title=element.text)

            try:
                if (
                    wait.WebDriverWait(driver, 60)
                    .until(ec.visibility_of_element_located((By.ID, "pnnext")))
                    .get_attribute("aria-disabled")
                    == "true"
                ):
                    break
            except wait.TimeoutException:
                break

            throttler.wait_for_slot(THROTTLING_QUEUE)

            try:
                driver.execute_script(
                    "arguments[0].click();",
                    wait.WebDriverWait(driver, 60).until(
                        ec.element_to_be_clickable((By.ID, "pnnext"))
                    ),
                )
            except wait.TimeoutException:
                break

            wait.WebDriverWait(driver, 60).until(ec.url_changes(current_url))
