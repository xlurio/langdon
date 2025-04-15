import { ForwardedRef, forwardRef } from "react";

interface CardProps extends React.HTMLProps<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
}

export default forwardRef<HTMLDivElement, CardProps>(function Card(
  { children, className, ...props }: CardProps,
  ref: ForwardedRef<HTMLDivElement>
) {
  return (
    <div className={`bg-card-bg shadow-md ${className}`} ref={ref} {...props}>
      {children}
    </div>
  );
});
