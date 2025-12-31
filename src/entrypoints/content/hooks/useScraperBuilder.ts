import { useEffect, useMemo, useState } from 'react';
import { updateState, type XcalibrState } from '../../../shared/state';
import {
  type ScraperDefinition,
  type ScraperDraft,
  type ScraperField,
  buildScraperId,
  extractScraperResults,
  getRegexMatchCount,
  generateCssSelector,
  generateXPath
} from '../../../shared/scraper';
import { ROOT_ID } from '../constants';

export type ScraperBuilderHook = {
  pickerRect: DOMRect | null;
  pickerLabel: string;
  pickerNotice: string | null;
  showScraperHelp: boolean;
  setShowScraperHelp: React.Dispatch<React.SetStateAction<boolean>>;
  regexPreviewMap: Map<string, { count: number; error: string | null; capped: boolean }>;
  activeScraper: ScraperDefinition | null;
  updateScraperDraft: (nextDraft: Partial<ScraperDraft>) => Promise<void>;
  openScraperBuilder: () => Promise<void>;
  closeScraperBuilder: () => Promise<void>;
  saveScraperDraft: () => Promise<void>;
  updateScraperField: (fieldId: string, next: Partial<ScraperField>) => Promise<void>;
  removeScraperField: (fieldId: string) => Promise<void>;
  openScraperRunner: (scraperId: string) => Promise<void>;
  rerunScraper: () => Promise<void>;
  closeScraperRunner: () => Promise<void>;
};

export const useScraperBuilder = (
  state: XcalibrState,
  setState: React.Dispatch<React.SetStateAction<XcalibrState>>
): ScraperBuilderHook => {
  const [pickerRect, setPickerRect] = useState<DOMRect | null>(null);
  const [pickerLabel, setPickerLabel] = useState('');
  const [pickerNotice, setPickerNotice] = useState<string | null>(null);
  const [showScraperHelp, setShowScraperHelp] = useState(false);

  const activeScraper = useMemo(
    () => state.scrapers.find((entry) => entry.id === state.scraperRunnerId) ?? null,
    [state.scrapers, state.scraperRunnerId]
  );

  const regexPreviewMap = useMemo(() => {
    const previews = new Map<string, { count: number; error: string | null; capped: boolean }>();
    if (!state.scraperBuilderOpen) return previews;
    const text = document.body?.innerText ?? '';
    state.scraperDraft.fields.forEach((field) => {
      if (field.source !== 'regex') return;
      previews.set(
        field.id,
        getRegexMatchCount(text, field.regex ?? '', field.regexFlags ?? '')
      );
    });
    return previews;
  }, [state.scraperBuilderOpen, state.scraperDraft.fields]);

  // Picker mode effect
  useEffect(() => {
    if (!state.scraperBuilderOpen || !state.scraperDraft.isPicking) return;

    const host = document.getElementById(ROOT_ID);

    const handleMove = (event: MouseEvent) => {
      const target = document.elementFromPoint(event.clientX, event.clientY);
      if (!target || (host && host.contains(target))) {
        setPickerRect(null);
        setPickerLabel('');
        return;
      }
      const rect = (target as Element).getBoundingClientRect();
      setPickerRect(rect);
      setPickerLabel(
        `${(target as Element).tagName.toLowerCase()}${(target as Element).id ? `#${(target as Element).id}` : ''}`
      );
    };

    const handleClick = (event: MouseEvent) => {
      const target = document.elementFromPoint(event.clientX, event.clientY);
      if (!target || (host && host.contains(target))) return;
      event.preventDefault();
      event.stopPropagation();
      const element = target as Element;
      const selector = generateCssSelector(element);
      const xpath = generateXPath(element);
      const isDuplicate = state.scraperDraft.fields.some(
        (field) => field.selector === selector || field.xpath === xpath
      );
      if (isDuplicate) {
        setPickerNotice('Element already added.');
        return;
      }
      const nextField: ScraperField = {
        id: `field_${Date.now()}_${Math.random().toString(16).slice(2)}`,
        name: `Field ${state.scraperDraft.fields.length + 1}`,
        selector,
        xpath,
        mode: 'single',
        source: 'text'
      };
      updateScraperDraft({ fields: [...state.scraperDraft.fields, nextField] });
      setPickerNotice('Element added.');
    };

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        updateScraperDraft({ isPicking: false });
        setPickerRect(null);
        setPickerLabel('');
      }
    };

    document.addEventListener('mousemove', handleMove, true);
    document.addEventListener('click', handleClick, true);
    window.addEventListener('keydown', handleKey, true);

    return () => {
      document.removeEventListener('mousemove', handleMove, true);
      document.removeEventListener('click', handleClick, true);
      window.removeEventListener('keydown', handleKey, true);
    };
  }, [state.scraperBuilderOpen, state.scraperDraft.isPicking, state.scraperDraft.fields.length]);

  // Clear picker notice after delay
  useEffect(() => {
    if (!pickerNotice) return;
    const timeout = window.setTimeout(() => setPickerNotice(null), 1400);
    return () => window.clearTimeout(timeout);
  }, [pickerNotice]);

  const updateScraperDraft = async (nextDraft: Partial<ScraperDraft>) => {
    const next = await updateState((current) => ({
      ...current,
      scraperDraft: {
        ...current.scraperDraft,
        ...nextDraft
      }
    }));
    setState(next);
  };

  const openScraperBuilder = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperBuilderOpen: true
    }));
    setState(next);
  };

  const closeScraperBuilder = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperBuilderOpen: false,
      scraperDraft: { ...current.scraperDraft, isPicking: false }
    }));
    setState(next);
    setPickerRect(null);
    setShowScraperHelp(false);
  };

  const saveScraperDraft = async () => {
    const draft = state.scraperDraft;
    if (!draft.name.trim() || draft.fields.length === 0) return;
    const now = Date.now();
    const newScraper: ScraperDefinition = {
      id: buildScraperId(),
      name: draft.name.trim(),
      fields: draft.fields,
      createdAt: now,
      updatedAt: now
    };
    const next = await updateState((current) => ({
      ...current,
      scrapers: [...current.scrapers, newScraper],
      scraperBuilderOpen: false,
      scraperDraft: { name: '', fields: [], isPicking: false }
    }));
    setState(next);
    setPickerRect(null);
  };

  const updateScraperField = async (fieldId: string, next: Partial<ScraperField>) => {
    const nextFields = state.scraperDraft.fields.map((field) =>
      field.id === fieldId ? { ...field, ...next } : field
    );
    await updateScraperDraft({ fields: nextFields });
  };

  const removeScraperField = async (fieldId: string) => {
    const nextFields = state.scraperDraft.fields.filter((field) => field.id !== fieldId);
    await updateScraperDraft({ fields: nextFields });
  };

  const openScraperRunner = async (scraperId: string) => {
    const scraper = state.scrapers.find((entry) => entry.id === scraperId);
    if (!scraper) return;
    const results = extractScraperResults(document, scraper);
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerOpen: true,
      scraperRunnerId: scraperId,
      scraperRunnerResults: results,
      scraperRunnerError: null
    }));
    setState(next);
  };

  const rerunScraper = async () => {
    if (!state.scraperRunnerId) return;
    const scraper = state.scrapers.find((entry) => entry.id === state.scraperRunnerId);
    if (!scraper) return;
    const results = extractScraperResults(document, scraper);
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerResults: results,
      scraperRunnerError: null
    }));
    setState(next);
  };

  const closeScraperRunner = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerOpen: false,
      scraperRunnerId: null,
      scraperRunnerError: null
    }));
    setState(next);
  };

  return {
    pickerRect,
    pickerLabel,
    pickerNotice,
    showScraperHelp,
    setShowScraperHelp,
    regexPreviewMap,
    activeScraper,
    updateScraperDraft,
    openScraperBuilder,
    closeScraperBuilder,
    saveScraperDraft,
    updateScraperField,
    removeScraperField,
    openScraperRunner,
    rerunScraper,
    closeScraperRunner
  };
};
