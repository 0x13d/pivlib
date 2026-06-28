import { GenericInspector } from './GenericInspector';
import { SAMPLES } from '../../samples';

export function Pkcs7Inspector() {
  return (
    <GenericInspector
      description="Drop a PKCS#7 / CMS SignedData envelope. pivlib enumerates the embedded certificates (each gets a CertSummary) and the SignerInfo entries (issuer + serial)."
      hint="PKCS#7 chain in DER / PEM"
      samples={SAMPLES.pkcs7}
      run={(api, b) => Promise.resolve(api.enumeratePkcs7(b))}
    />
  );
}
