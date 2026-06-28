import { GenericInspector } from './GenericInspector';

export function CsrInspector() {
  return (
    <GenericInspector
      description="Drop a PKCS#10 Certificate Signing Request. Encoding is detected automatically; the parser returns subject, public-key algorithm, signature algorithm, and any requested attributes."
      hint="DER / PEM / base64-of-DER"
      run={(api, b) => Promise.resolve(api.parseCsr(b))}
    />
  );
}
