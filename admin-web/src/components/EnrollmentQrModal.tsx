import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { Button, Modal } from "./ui";

export type EnrollmentQr = {
  payload: string;
  title: string;
};

export function EnrollmentQrModal(props: {
  enrollment: EnrollmentQr | null;
  onClose: () => void;
  onCopy: (value: string, label?: string) => void;
}) {
  const [dataUrl, setDataUrl] = useState("");
  const [failed, setFailed] = useState(false);
  const payload = props.enrollment?.payload ?? "";

  useEffect(() => {
    if (!payload) return undefined;
    let canceled = false;
    setDataUrl("");
    setFailed(false);
    void QRCode.toDataURL(payload, { errorCorrectionLevel: "M", margin: 2, scale: 9 })
      .then((url) => {
        if (!canceled) setDataUrl(url);
      })
      .catch(() => {
        if (!canceled) setFailed(true);
      });
    return () => {
      canceled = true;
    };
  }, [payload]);

  return (
    <Modal
      description="Open PushGate on your phone, then scan this code to complete enrollment."
      footer={
        <>
          <Button onClick={props.onClose} variant="secondary">
            Done
          </Button>
          <Button icon="copy" onClick={() => payload && props.onCopy(payload, "Enrollment payload copied")}>
            Copy payload
          </Button>
        </>
      }
      onClose={props.onClose}
      open={Boolean(props.enrollment)}
      size="lg"
      title={props.enrollment?.title ?? "Enrollment"}
    >
      <div className="enrollment-layout">
        <div className="qr-frame">
          {dataUrl ? <img alt="PushGate device enrollment QR code" src={dataUrl} /> : <span>{failed ? "QR unavailable" : "Rendering QR"}</span>}
        </div>
        <div className="enrollment-copy">
          <ol>
            <li>Open PushGate on your phone.</li>
            <li>Choose Scan.</li>
            <li>Point the camera at this QR code.</li>
          </ol>
          <pre>{payload}</pre>
        </div>
      </div>
    </Modal>
  );
}
