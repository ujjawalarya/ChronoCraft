import React, { useEffect, useState } from 'react';
import { loadSavedTheme, saveTheme, type AppTheme } from '../utils/storage';
import { Check, Leaf, Moon, Palette, Sun } from 'lucide-react';

const THEMES: { id: AppTheme; label: string; description: string; swatches: string[]; Icon: typeof Sun }[] = [
  { id: 'light', label: 'Light', description: 'Crisp and bright', swatches: ['#f8fafc', '#ffffff', '#6366f1'], Icon: Sun },
  { id: 'dark', label: 'Dark', description: 'Classic deep navy', swatches: ['#0f172a', '#1e293b', '#818cf8'], Icon: Moon },
  { id: 'midnight', label: 'Midnight', description: 'Charcoal with a quiet teal glow', swatches: ['#101714', '#1b2420', '#7fc9a2'], Icon: Moon },
  { id: 'sage', label: 'Sage', description: 'Soft, grounded forest greens', swatches: ['#e8efe8', '#f5f8f4', '#47765b'], Icon: Leaf },
];

export const ThemeToggle: React.FC = () => {
  const [theme, setTheme] = useState<AppTheme>(() => loadSavedTheme());
  const [isOpen, setIsOpen] = useState(false);
  const selectedTheme = THEMES.find((option) => option.id === theme) ?? THEMES[1];
  const SelectedIcon = selectedTheme.Icon;

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark' || theme === 'midnight');
    root.dataset.theme = theme;
    saveTheme(theme);
  }, [theme]);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setIsOpen((open) => !open)}
        className="p-2 sm:p-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-all border border-slate-200 dark:border-slate-700 focus:outline-none flex items-center gap-2"
        title={`Appearance: ${selectedTheme.label}`}
        aria-label={`Appearance: ${selectedTheme.label}`}
        aria-haspopup="menu"
        aria-expanded={isOpen}
      >
        <SelectedIcon className="w-4 h-4" aria-hidden="true" />
        <span className="text-xs font-semibold hidden md:inline">{selectedTheme.label}</span>
        <Palette className="w-3.5 h-3.5 opacity-60" aria-hidden="true" />
      </button>

      {isOpen && (
        <>
          <button className="fixed inset-0 z-40 cursor-default" aria-label="Close appearance menu" onClick={() => setIsOpen(false)} />
          <div role="menu" aria-label="Choose appearance" className="absolute right-0 top-full mt-2 w-64 rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-2 shadow-2xl z-50">
            <div className="px-2.5 pt-1 pb-2">
              <p className="text-xs font-bold text-slate-800 dark:text-slate-100">Choose your atmosphere</p>
              <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">A calmer canvas for every session.</p>
            </div>
            {THEMES.map(({ id, label, description, swatches, Icon }) => (
              <button
                key={id}
                type="button"
                role="menuitemradio"
                aria-checked={theme === id}
                onClick={() => { setTheme(id); setIsOpen(false); }}
                className={`w-full flex items-center gap-2.5 rounded-xl p-2.5 text-left transition-colors ${theme === id ? 'bg-emerald-50 dark:bg-emerald-950/40' : 'hover:bg-slate-50 dark:hover:bg-slate-800'}`}
              >
                <span className="flex -space-x-1 shrink-0" aria-hidden="true">
                  {swatches.map((color) => <span key={color} className="w-4 h-4 rounded-full border-2 border-white dark:border-slate-900" style={{ backgroundColor: color }} />)}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-1.5 text-xs font-bold text-slate-800 dark:text-slate-100"><Icon className="w-3.5 h-3.5" />{label}</span>
                  <span className="block text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">{description}</span>
                </span>
                {theme === id && <Check className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" aria-hidden="true" />}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
};
