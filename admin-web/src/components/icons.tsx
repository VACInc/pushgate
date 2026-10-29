import type { SVGProps } from "react";

export type IconName =
  | "activity"
  | "alert"
  | "check"
  | "chevron-left"
  | "copy"
  | "dashboard"
  | "devices"
  | "groups"
  | "integrations"
  | "keys"
  | "lock"
  | "logs"
  | "menu"
  | "moon"
  | "plus"
  | "policies"
  | "refresh"
  | "search"
  | "settings"
  | "shield-check"
  | "sun"
  | "trash"
  | "unlock"
  | "users"
  | "x";

type IconProps = SVGProps<SVGSVGElement> & {
  name: IconName;
  size?: number;
};

export function Icon({ name, size = 18, ...props }: IconProps) {
  return (
    <svg
      aria-hidden="true"
      fill="none"
      height={size}
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.8"
      viewBox="0 0 24 24"
      width={size}
      {...props}
    >
      {pathFor(name)}
    </svg>
  );
}

function pathFor(name: IconName) {
  switch (name) {
    case "activity":
      return <path d="M3 12h4l2.5-7 5 14 2.5-7h4" />;
    case "alert":
      return (
        <>
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
          <path d="M10.3 4.2 2.8 17.1A2 2 0 0 0 4.5 20h15a2 2 0 0 0 1.7-2.9L13.7 4.2a2 2 0 0 0-3.4 0Z" />
        </>
      );
    case "check":
      return <path d="m5 12 4 4 10-10" />;
    case "chevron-left":
      return <path d="m15 18-6-6 6-6" />;
    case "copy":
      return (
        <>
          <rect height="13" rx="2" width="13" x="8" y="8" />
          <path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" />
        </>
      );
    case "dashboard":
      return (
        <>
          <rect height="7" rx="1.5" width="7" x="3" y="3" />
          <rect height="7" rx="1.5" width="7" x="14" y="3" />
          <rect height="7" rx="1.5" width="7" x="14" y="14" />
          <rect height="7" rx="1.5" width="7" x="3" y="14" />
        </>
      );
    case "devices":
      return (
        <>
          <rect height="18" rx="3" width="11" x="6.5" y="3" />
          <path d="M10 17h4" />
        </>
      );
    case "groups":
      return (
        <>
          <path d="M16 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2" />
          <circle cx="9.5" cy="7" r="4" />
          <path d="M22 21v-2a4 4 0 0 0-3-3.9" />
          <path d="M16 3.2a4 4 0 0 1 0 7.6" />
        </>
      );
    case "integrations":
      return (
        <>
          <path d="M7 7h10v10H7z" />
          <path d="M4 12H2" />
          <path d="M22 12h-2" />
          <path d="M12 4V2" />
          <path d="M12 22v-2" />
          <path d="M17 7l2-2" />
          <path d="M5 19l2-2" />
          <path d="M7 7 5 5" />
          <path d="m19 19-2-2" />
        </>
      );
    case "keys":
      return (
        <>
          <circle cx="7.5" cy="14.5" r="3.5" />
          <path d="m10 12 9-9" />
          <path d="m15 4 2 2" />
          <path d="m13 6 2 2" />
        </>
      );
    case "lock":
      return (
        <>
          <rect height="11" rx="2" width="16" x="4" y="10" />
          <path d="M8 10V7a4 4 0 0 1 8 0v3" />
        </>
      );
    case "logs":
      return (
        <>
          <path d="M8 6h13" />
          <path d="M8 12h13" />
          <path d="M8 18h13" />
          <path d="M3 6h.01" />
          <path d="M3 12h.01" />
          <path d="M3 18h.01" />
        </>
      );
    case "menu":
      return (
        <>
          <path d="M4 6h16" />
          <path d="M4 12h16" />
          <path d="M4 18h16" />
        </>
      );
    case "moon":
      return <path d="M21 12.8A8.5 8.5 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" />;
    case "plus":
      return (
        <>
          <path d="M12 5v14" />
          <path d="M5 12h14" />
        </>
      );
    case "policies":
      return (
        <>
          <path d="M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6l-8-3Z" />
          <path d="M9 12h6" />
          <path d="M9 16h6" />
          <path d="M9 8h6" />
        </>
      );
    case "refresh":
      return (
        <>
          <path d="M20 12a8 8 0 0 1-14.9 4" />
          <path d="M4 12A8 8 0 0 1 18.9 8" />
          <path d="M18 3v5h-5" />
          <path d="M6 21v-5h5" />
        </>
      );
    case "search":
      return (
        <>
          <circle cx="11" cy="11" r="7" />
          <path d="m20 20-3.5-3.5" />
        </>
      );
    case "settings":
      return (
        <>
          <path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z" />
          <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1A2 2 0 1 1 4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.3 7A2 2 0 1 1 7.1 4.2l.1.1a1.7 1.7 0 0 0 1.9.3h.1a1.7 1.7 0 0 0 1-1.6V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.6h.1a1.7 1.7 0 0 0 1.9-.3l.1-.1A2 2 0 1 1 20 7.1l-.1.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.6 1h.1a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.8.8Z" />
        </>
      );
    case "shield-check":
      return (
        <>
          <path d="M12 3 4.5 6v5.7c0 4.7 3.2 8 7.5 9.3 4.3-1.3 7.5-4.6 7.5-9.3V6L12 3Z" />
          <path d="m8.8 12 2.1 2.1 4.4-4.6" />
        </>
      );
    case "sun":
      return (
        <>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2" />
          <path d="M12 20v2" />
          <path d="m4.9 4.9 1.4 1.4" />
          <path d="m17.7 17.7 1.4 1.4" />
          <path d="M2 12h2" />
          <path d="M20 12h2" />
          <path d="m4.9 19.1 1.4-1.4" />
          <path d="m17.7 6.3 1.4-1.4" />
        </>
      );
    case "trash":
      return (
        <>
          <path d="M3 6h18" />
          <path d="M8 6V4h8v2" />
          <path d="M19 6l-1 15H6L5 6" />
          <path d="M10 11v6" />
          <path d="M14 11v6" />
        </>
      );
    case "unlock":
      return (
        <>
          <rect height="11" rx="2" width="16" x="4" y="10" />
          <path d="M8 10V7a4 4 0 0 1 7.5-2" />
        </>
      );
    case "users":
      return (
        <>
          <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
          <circle cx="9" cy="7" r="4" />
          <path d="M22 21v-2a4 4 0 0 0-3-3.8" />
          <path d="M16 3.2a4 4 0 0 1 0 7.6" />
        </>
      );
    case "x":
      return (
        <>
          <path d="M18 6 6 18" />
          <path d="m6 6 12 12" />
        </>
      );
  }
}
