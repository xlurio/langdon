from __future__ import annotations

import abc
import shutil
import tempfile
import time
from typing import TYPE_CHECKING, cast

import pydub
import requests
import speech_recognition as sr
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox import options, service, webdriver
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support import wait

from langdon import throttler
from langdon.exceptions import LangdonException

if TYPE_CHECKING:
    from collections.abc import Iterator

    from langdon.langdon_manager import LangdonManager

BASE_URL = "https://google.com"
THROTTLING_QUEUE = "throttler_google"


class GoogleRecognizerType(sr.Recognizer):
    @abc.abstractmethod
    def recognize_google(
        self, audio_data, key=None, language="en-US", show_all=False
    ) -> str:
        raise NotImplementedError


def _make_webdriver(*, manager: LangdonManager) -> webdriver.WebDriver:
    wd_options = options.Options()
    wd_options.add_argument("--headless")

    if firefox_profile := manager.config.get("firefox_profile"):
        wd_options.set_preference("profile", firefox_profile)

    wd_options.set_preference("network.proxy.type", 1)
    wd_options.set_preference("network.proxy.socks", manager.config["socks_proxy_host"])
    wd_options.set_preference("network.proxy.socks_port", manager.config["socks_proxy_port"])
    wd_options.set_preference(
        "general.useragent.override", manager.config["user_agent"]
    )

    wd_service = service.Service(shutil.which("geckodriver"))

    return webdriver.WebDriver(options=wd_options, service=wd_service)


def _solve_captcha(driver: webdriver.WebDriver, *, manager: LangdonManager) -> None:
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
                throttler.wait_for_slot(THROTTLING_QUEUE, manager=manager)
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
            throttler.wait_for_slot(THROTTLING_QUEUE, manager=manager)
            wait.WebDriverWait(driver, 60).until(
                ec.element_to_be_clickable((By.ID, "recaptcha-verify-button"))
            ).click()
            wait.WebDriverWait(driver, 60).until(ec.url_changes(current_url))
    except wait.TimeoutException:
        raise LangdonException("Could not solve the captcha")


def enumerate_directories_with_google(domain: str, *, manager: LangdonManager) -> Iterator[str]:
    with _make_webdriver(manager=manager) as driver:
        _initialize_search(driver, domain, manager=manager)
        while True:
            yield from _extract_results(driver, domain)
            if not _navigate_to_next_page(driver, manager=manager):
                break


def _initialize_search(
    driver: webdriver.WebDriver, domain: str, *, manager: LangdonManager
) -> None:
    throttler.wait_for_slot(THROTTLING_QUEUE, manager=manager)
    driver.get(f"https://google.com/search?q=site:{domain}")
    time.sleep(5)
    if driver.current_url.startswith("https://www.google.com/sorry"):
        _solve_captcha(driver, manager=manager)


def _extract_results(driver: webdriver.WebDriver, domain: str) -> Iterator[str]:
    for element in driver.find_elements(By.XPATH, "//h3"):
        result_url = element.find_element(By.XPATH, "..").get_attribute("href")
        if result_url and (("*" in domain) or (domain in result_url)):
            yield result_url


def _navigate_to_next_page(
    driver: webdriver.WebDriver, *, manager: LangdonManager
) -> bool:
    try:
        next_button = wait.WebDriverWait(driver, 60).until(
            ec.visibility_of_element_located((By.ID, "pnnext"))
        )
        if next_button.get_attribute("aria-disabled") == "true":
            return False
        throttler.wait_for_slot(THROTTLING_QUEUE, manager=manager)
        driver.execute_script("arguments[0].click();", next_button)
        wait.WebDriverWait(driver, 60).until(ec.url_changes(driver.current_url))
        return True
    except wait.TimeoutException:
        return False
