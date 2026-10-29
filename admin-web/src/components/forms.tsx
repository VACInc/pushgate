import type { FailMode } from "../api";
import { Select } from "./ui";

export function FailModeSelect(props: {
  disabled?: boolean;
  name?: string;
  onChange?: (value: string) => void;
  value?: string | null;
  defaultValue?: string;
}) {
  return (
    <Select
      defaultValue={props.defaultValue}
      disabled={props.disabled}
      name={props.name}
      onChange={props.onChange ? (event) => props.onChange?.(event.target.value) : undefined}
      value={props.value ?? undefined}
    >
      <option value="">Inherit</option>
      <option value="open">Open</option>
      <option value="closed">Closed</option>
    </Select>
  );
}

export function RequiredFailModeSelect(props: { defaultValue: FailMode; name: string }) {
  return (
    <Select defaultValue={props.defaultValue} name={props.name}>
      <option value="open">Open</option>
      <option value="closed">Closed</option>
    </Select>
  );
}

export function PolicyBiometricSelect(props: { name: string }) {
  return (
    <Select defaultValue="" name={props.name}>
      <option value="">Inherit biometric</option>
      <option value="true">Require biometric</option>
      <option value="false">Do not require</option>
    </Select>
  );
}
