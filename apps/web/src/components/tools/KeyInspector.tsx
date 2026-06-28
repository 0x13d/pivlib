import { GenericInspector } from './GenericInspector';
import { SAMPLES } from '../../samples';

export function KeyInspector() {
  return (
    <GenericInspector
      description="Drop a PKCS#8 private key, encrypted or plain. pivlib reports the algorithm, the parameters (named curve / RSA modulus length / etc), and the encryption envelope when applicable. The actual key material is never returned."
      hint="PKCS#8 in DER / PEM / base64"
      samples={SAMPLES.key}
      run={(api, b) => Promise.resolve(api.parseKeyMetadata(b))}
    />
  );
}
