import { Button, Modal } from "./ui";

export function SecretModal(props: {
  onClose: () => void;
  onCopy: (value: string, label?: string) => void;
  secret: string;
}) {
  const [title, ...rest] = props.secret.split("\n");
  const body = rest.join("\n").trim();

  return (
    <Modal
      description="This value may only be available once. Store it before closing."
      footer={
        <>
          <Button onClick={props.onClose} variant="secondary">
            Close
          </Button>
          <Button disabled={!props.secret} icon="copy" onClick={() => props.onCopy(props.secret, "Secret copied")}>
            Copy
          </Button>
        </>
      }
      onClose={props.onClose}
      open={Boolean(props.secret)}
      size="lg"
      title={title || "Secret"}
    >
      <pre className="secret-block">{body || props.secret}</pre>
    </Modal>
  );
}
