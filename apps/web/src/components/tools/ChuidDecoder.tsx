import { GenericInspector } from './GenericInspector';
import { SAMPLES } from '../../samples';

export function ChuidDecoder() {
  return (
    <GenericInspector
      description="Drop a PIV CHUID container (SP 800-73 Part 1, §3.1.2). pivlib walks the BER-TLVs and returns the FASC-N (decoded into its named fields), GUID, expiration date, agency codes, and the issuer asymmetric signature reference."
      hint="Raw CHUID bytes (no encoding detection)"
      normalize={false}
      samples={SAMPLES.chuid}
      run={(api, b) => Promise.resolve(api.parseChuid(b))}
    />
  );
}
