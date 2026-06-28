import { useRef, useState, type DragEvent } from 'react';

interface FileDropProps {
  onFile: (bytes: Uint8Array, name: string) => void;
  accept?: string;
  hint?: string;
}

export function FileDrop({ onFile, accept, hint }: FileDropProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);

  async function handle(file: File) {
    const buf = await file.arrayBuffer();
    onFile(new Uint8Array(buf), file.name);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) void handle(file);
  }

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={onDrop}
      onClick={() => inputRef.current?.click()}
      className={`cursor-pointer border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
        dragOver ? 'border-ember bg-paperDim/60' : 'border-ink/15 hover:border-ink/40'
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void handle(f);
        }}
      />
      <p className="text-[15px] text-ink">Drop a file here, or click to choose.</p>
      {hint ? <p className="mt-1 text-[12.5px] text-inkSoft">{hint}</p> : null}
    </div>
  );
}
