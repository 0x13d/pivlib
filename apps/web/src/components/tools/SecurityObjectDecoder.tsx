import { GenericInspector } from './GenericInspector';
import { SAMPLES } from '../../samples';

export function SecurityObjectDecoder() {
  return (
    <GenericInspector
      description="Drop a PIV Security Object (SP 800-73 Part 1, §3.5.5) — structurally a CMS SignedData wrapping an LDSSecurityObject. pivlib returns the signer info, the hash algorithm, and the per-container `(container_id, hash)` pairs."
      hint="DER / PEM / base64 of a CMS SignedData"
      samples={SAMPLES.securityObject}
      run={(api, b) => Promise.resolve(api.parseSecurityObject(b))}
    />
  );
}
