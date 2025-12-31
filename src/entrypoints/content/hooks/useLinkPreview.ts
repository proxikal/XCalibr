import { useEffect, useRef } from 'react';
import type { XcalibrState } from '../../../shared/state';
import type { LiveLinkPreviewData } from '../Tools/tool-types';
import {
  createPreviewHost,
  isValidPreviewUrl,
  isKnownBlockingSite,
  getPreviewFallbackMessage,
  PREVIEW_SCALE,
  PREVIEW_WIDTH,
  PREVIEW_HEIGHT,
  PREVIEW_MARGIN
} from '../Tools/helpers';
import { ROOT_ID } from '../constants';

type PreviewHostRefs = {
  host: HTMLDivElement;
  wrapper: HTMLDivElement;
  frame: HTMLIFrameElement;
  title: HTMLDivElement;
  fallback: HTMLDivElement;
};

export const useLinkPreview = (state: XcalibrState): void => {
  const linkPreviewHostRef = useRef<PreviewHostRefs | null>(null);
  const linkPreviewAnchorRef = useRef<HTMLAnchorElement | null>(null);
  const linkPreviewTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    const isActive = Boolean(
      (state.toolData.liveLinkPreview as LiveLinkPreviewData | undefined)?.isActive
    );
    if (!isActive) {
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
        linkPreviewTimeoutRef.current = null;
      }
      if (linkPreviewHostRef.current) {
        linkPreviewHostRef.current.host.remove();
        linkPreviewHostRef.current = null;
      }
      linkPreviewAnchorRef.current = null;
      return;
    }

    const hidePreview = () => {
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
        linkPreviewTimeoutRef.current = null;
      }
      if (linkPreviewHostRef.current) {
        linkPreviewHostRef.current.host.remove();
        linkPreviewHostRef.current = null;
      }
      linkPreviewAnchorRef.current = null;
    };

    const showPreview = (anchor: HTMLAnchorElement) => {
      const href = anchor.getAttribute('href') ?? '';
      if (!href || !isValidPreviewUrl(anchor.href)) return;
      if (!linkPreviewHostRef.current) {
        linkPreviewHostRef.current = createPreviewHost();
      }
      const { wrapper, frame, title, fallback } = linkPreviewHostRef.current;
      title.textContent = anchor.href;

      const isBlocked = isKnownBlockingSite(anchor.href);

      if (isBlocked) {
        frame.classList.add('hidden');
        frame.src = 'about:blank';
        fallback.classList.add('visible');
        const messageEl = fallback.querySelector('.preview-fallback-message');
        if (messageEl) {
          messageEl.textContent = getPreviewFallbackMessage(anchor.href);
        }
      } else {
        frame.classList.remove('hidden');
        fallback.classList.remove('visible');
        frame.src = anchor.href;

        frame.onerror = () => {
          frame.classList.add('hidden');
          fallback.classList.add('visible');
          const messageEl = fallback.querySelector('.preview-fallback-message');
          if (messageEl) {
            messageEl.textContent = getPreviewFallbackMessage(anchor.href);
          }
        };
      }

      const rect = anchor.getBoundingClientRect();
      const width = PREVIEW_WIDTH * PREVIEW_SCALE;
      const height = PREVIEW_HEIGHT * PREVIEW_SCALE;
      const fitsBelow = rect.bottom + height + PREVIEW_MARGIN < window.innerHeight;
      const top = fitsBelow
        ? rect.bottom + PREVIEW_MARGIN
        : Math.max(PREVIEW_MARGIN, rect.top - height - PREVIEW_MARGIN);
      const left = Math.min(
        Math.max(PREVIEW_MARGIN, rect.left),
        window.innerWidth - width - PREVIEW_MARGIN
      );
      wrapper.style.top = `${top}px`;
      wrapper.style.left = `${left}px`;
    };

    const handleMouseOver = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (!target) return;
      const host = document.getElementById(ROOT_ID);
      if (host && host.contains(target)) return;
      const anchor = target.closest('a') as HTMLAnchorElement | null;
      if (!anchor || !anchor.href) return;
      if (linkPreviewAnchorRef.current === anchor) return;
      linkPreviewAnchorRef.current = anchor;
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
      }
      linkPreviewTimeoutRef.current = window.setTimeout(() => {
        showPreview(anchor);
      }, 500);
    };

    const handleMouseOut = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (!target) return;
      const anchor = target.closest('a') as HTMLAnchorElement | null;
      if (!anchor || anchor !== linkPreviewAnchorRef.current) return;
      hidePreview();
    };

    document.addEventListener('mouseover', handleMouseOver);
    document.addEventListener('mouseout', handleMouseOut);
    return () => {
      document.removeEventListener('mouseover', handleMouseOver);
      document.removeEventListener('mouseout', handleMouseOut);
      hidePreview();
    };
  }, [state.toolData.liveLinkPreview]);
};
