import { GenericInspector } from './GenericInspector';
import { SAMPLES } from '../../samples';

export function CrlInspector() {
  return (
    <GenericInspector
      description="Drop an X.509 Certificate Revocation List. Returns issuer, this_update / next_update, and the revoked-serial table."
      hint="DER / PEM / base64-of-DER"
      samples={SAMPLES.crl}
      run={(api, b) => Promise.resolve(api.parseCrl(b))}
    />
  );
}
