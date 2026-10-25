import React from 'react';
import { AlertTriangle, X } from 'lucide-react';

const ConfirmationModal = ({
  isOpen,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  isDanger = false,
  onConfirm,
  onClose,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/65 backdrop-blur-md animate-fadeIn">
      <div className="relative w-full max-w-md bg-[#253750] border border-[#364D6E]/80 rounded-2xl shadow-2xl p-6 overflow-hidden">
        {/* Glow accent bar */}
        <div className={`absolute top-0 left-0 right-0 h-1 ${
          isDanger
            ? 'bg-gradient-to-r from-[#FF7185] to-[#F5BD61] shadow-[0_0_12px_rgba(255,113,133,0.4)]'
            : 'bg-gradient-to-r from-[#5B8DEF] to-[#43D6C5] shadow-[0_0_12px_rgba(91,141,239,0.4)]'
        }`} />

        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border shadow-neumorph-sm ${
              isDanger
                ? 'bg-[#FF7185]/15 border-[#FF7185]/35 text-[#FF7185]'
                : 'bg-[#5B8DEF]/15 border-[#5B8DEF]/35 text-[#5B8DEF]'
            }`}>
              <AlertTriangle className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-[#F3F6FC] tracking-wide">{title}</h3>
          </div>
          <button
            onClick={onClose}
            className="text-[#B8C5D8] hover:text-[#F3F6FC] transition-colors p-1 rounded-lg hover:bg-[#1E2F46]"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-xs sm:text-sm text-[#B8C5D8] leading-relaxed mb-6 font-sans">
          {message}
        </p>

        <div className="flex items-center justify-end gap-3 font-mono-code text-xs">
          <button
            onClick={onClose}
            className="px-4 py-2 font-medium text-[#B8C5D8] hover:text-[#F3F6FC] bg-[#1E2F46] border border-[#364D6E]/50 rounded-lg transition-all hover:bg-[#2B3F59] shadow-neumorph-sm"
          >
            {cancelText}
          </button>
          <button
            onClick={() => {
              onConfirm();
              onClose();
            }}
            className={`px-4 py-2 font-semibold rounded-lg transition-all shadow-md ${
              isDanger
                ? 'bg-[#FF7185] hover:bg-[#FF7185]/90 text-white shadow-[0_0_15px_rgba(255,113,133,0.3)]'
                : 'bg-[#5B8DEF] hover:bg-[#5B8DEF]/90 text-white shadow-[0_0_15px_rgba(91,141,239,0.3)]'
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmationModal;
