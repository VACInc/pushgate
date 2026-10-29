import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { useEffect } from "react";
import { classNames } from "../utils";
import { Icon, type IconName } from "./icons";

export type Tone = "success" | "danger" | "warning" | "info" | "neutral";

export type Toast = {
  id: number;
  message: string;
  tone: Tone;
};

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  icon?: IconName;
  iconOnly?: boolean;
  size?: "sm" | "md";
  variant?: "primary" | "secondary" | "ghost" | "danger" | "soft";
};

export function Button({ children, className, icon, iconOnly, size = "md", type = "button", variant = "primary", ...props }: ButtonProps) {
  return (
    <button
      className={classNames("btn", `btn--${variant}`, `btn--${size}`, iconOnly && "btn--icon", className)}
      title={props.title ?? (iconOnly && typeof children === "string" ? children : undefined)}
      type={type}
      {...props}
    >
      {icon && <Icon name={icon} size={size === "sm" ? 16 : 18} />}
      {children && <span>{children}</span>}
    </button>
  );
}

export function IconButton(props: Omit<ButtonProps, "children" | "iconOnly"> & { label: string; icon: IconName }) {
  const { label, ...buttonProps } = props;
  return (
    <Button aria-label={label} iconOnly title={label} {...buttonProps}>
      {label}
    </Button>
  );
}

export function Card(props: { children: ReactNode; className?: string; padded?: boolean }) {
  return <section className={classNames("card", props.padded !== false && "card--padded", props.className)}>{props.children}</section>;
}

export function SectionHeader(props: { actions?: ReactNode; eyebrow?: string; title: string; description?: string }) {
  return (
    <div className="section-header">
      <div>
        {props.eyebrow && <p className="eyebrow">{props.eyebrow}</p>}
        <h2>{props.title}</h2>
        {props.description && <p>{props.description}</p>}
      </div>
      {props.actions && <div className="section-actions">{props.actions}</div>}
    </div>
  );
}

export function Field(props: { children: ReactNode; label: string; hint?: string; inline?: boolean }) {
  return (
    <label className={classNames("field", props.inline && "field--inline")}>
      <span>{props.label}</span>
      {props.children}
      {props.hint && <small>{props.hint}</small>}
    </label>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} />;
}

export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} />;
}

export function Chip(props: { children: ReactNode; tone?: Tone; className?: string }) {
  return <span className={classNames("chip", `chip--${props.tone ?? "neutral"}`, props.className)}>{props.children}</span>;
}

export function StatusChip(props: { status?: string | null; tone?: Tone }) {
  return <Chip tone={props.tone}>{props.status || "unknown"}</Chip>;
}

export function StatTile(props: { accent?: Tone; icon?: IconName; label: string; value: ReactNode; detail?: ReactNode }) {
  return (
    <Card className={classNames("stat-tile", props.accent && `stat-tile--${props.accent}`)}>
      <div className="stat-icon">{props.icon && <Icon name={props.icon} size={20} />}</div>
      <div>
        <p>{props.label}</p>
        <strong>{props.value}</strong>
        {props.detail && <span>{props.detail}</span>}
      </div>
    </Card>
  );
}

export function EmptyState(props: { title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-state__icon">
        <Icon name="shield-check" size={22} />
      </div>
      <strong>{props.title}</strong>
      {props.description && <p>{props.description}</p>}
      {props.action && <div>{props.action}</div>}
    </div>
  );
}

export function SkeletonRows(props: { rows?: number }) {
  return (
    <div className="skeleton-stack" aria-hidden="true">
      {Array.from({ length: props.rows ?? 4 }).map((_, index) => (
        <div className="skeleton-row" key={index} />
      ))}
    </div>
  );
}

export function SearchField(props: { value: string; onChange: (value: string) => void; placeholder?: string }) {
  return (
    <label className="search-field">
      <Icon name="search" size={17} />
      <input aria-label="Search" onChange={(event) => props.onChange(event.target.value)} placeholder={props.placeholder ?? "Search"} value={props.value} />
    </label>
  );
}

export function Modal(props: {
  children: ReactNode;
  description?: string;
  footer?: ReactNode;
  onClose: () => void;
  open: boolean;
  size?: "sm" | "md" | "lg";
  title: string;
}) {
  useEscape(props.open, props.onClose);
  if (!props.open) return null;

  return (
    <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section aria-modal="true" className={classNames("modal", `modal--${props.size ?? "md"}`)} role="dialog">
        <div className="modal__header">
          <div>
            <h2>{props.title}</h2>
            {props.description && <p>{props.description}</p>}
          </div>
          <IconButton icon="x" label="Close" onClick={props.onClose} variant="ghost" />
        </div>
        <div className="modal__body">{props.children}</div>
        {props.footer && <div className="modal__footer">{props.footer}</div>}
      </section>
    </div>
  );
}

export function Drawer(props: {
  children: ReactNode;
  description?: string;
  onClose: () => void;
  open: boolean;
  title: string;
}) {
  useEscape(props.open, props.onClose);
  if (!props.open) return null;

  return (
    <div className="overlay overlay--drawer" onMouseDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <aside aria-modal="true" className="drawer" role="dialog">
        <div className="modal__header">
          <div>
            <h2>{props.title}</h2>
            {props.description && <p>{props.description}</p>}
          </div>
          <IconButton icon="x" label="Close" onClick={props.onClose} variant="ghost" />
        </div>
        <div className="drawer__body">{props.children}</div>
      </aside>
    </div>
  );
}

export function ConfirmDialog(props: {
  confirmLabel?: string;
  description: string;
  onClose: () => void;
  onConfirm: () => void;
  open: boolean;
  title: string;
  tone?: "danger" | "warning";
}) {
  return (
    <Modal
      footer={
        <>
          <Button onClick={props.onClose} variant="secondary">
            Cancel
          </Button>
          <Button icon={props.tone === "danger" ? "trash" : "check"} onClick={props.onConfirm} variant={props.tone === "danger" ? "danger" : "primary"}>
            {props.confirmLabel ?? "Confirm"}
          </Button>
        </>
      }
      onClose={props.onClose}
      open={props.open}
      size="sm"
      title={props.title}
    >
      <p className="confirm-copy">{props.description}</p>
    </Modal>
  );
}

export function ToastViewport(props: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div aria-live="polite" className="toast-viewport">
      {props.toasts.map((toast) => (
        <div className={classNames("toast", `toast--${toast.tone}`)} key={toast.id}>
          <Icon name={toast.tone === "danger" ? "alert" : "check"} size={17} />
          <span>{toast.message}</span>
          <IconButton icon="x" label="Dismiss notification" onClick={() => props.onDismiss(toast.id)} size="sm" variant="ghost" />
        </div>
      ))}
    </div>
  );
}

export function Toggle(props: { checked: boolean; disabled?: boolean; label: string; onChange: (checked: boolean) => void }) {
  return (
    <label className="toggle">
      <input checked={props.checked} disabled={props.disabled} onChange={(event) => props.onChange(event.target.checked)} type="checkbox" />
      <span aria-hidden="true" />
      <strong>{props.label}</strong>
    </label>
  );
}

function useEscape(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose, open]);
}
