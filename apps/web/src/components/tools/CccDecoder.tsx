import { GenericInspector } from './GenericInspector';
import { SAMPLES } from '../../samples';

export function CccDecoder() {
  return (
    <GenericInspector
      description="Drop a PIV Card Capability Container (SP 800-73 Part 1, §3.1.1). pivlib decodes the named tag set; anything else lands in `extras` so you can see what the card vendor included."
      hint="Raw CCC bytes (no encoding detection)"
      normalize={false}
      samples={SAMPLES.ccc}
      run={(api, b) => Promise.resolve(api.parseCcc(b))}
    />
  );
}
