import { GenericInspector } from './GenericInspector';
import { SAMPLES } from '../../samples';

export function Pkcs12Inspector() {
  return (
    <GenericInspector
      description="Drop a PKCS#12 / PFX bundle. pivlib reports the structure — version, AuthSafe content type, MAC algorithm — without attempting to decrypt. A future enumerate_with_password() entrypoint will surface SafeBag contents."
      hint="PKCS#12 (.p12 / .pfx)"
      samples={SAMPLES.pkcs12}
      run={(api, b) => Promise.resolve(api.enumeratePkcs12(b))}
    />
  );
}
