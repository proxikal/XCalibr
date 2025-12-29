/**
 * Hooks for Features State
 */

import { useCallback } from 'react';
import { useAppStore } from './useAppStore';

export function useFeatures() {
  const [state, setState] = useAppStore();

  const toggleFeature = useCallback(
    (featureId: string) => {
      setState((currentState) => ({
        featuresState: {
          ...currentState.featuresState,
          features: currentState.featuresState.features.map((f) =>
            f.id === featureId ? { ...f, enabled: !f.enabled } : f
          ),
        },
      }));

      // Notify content script of feature toggle
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'TOGGLE_FEATURE',
            data: {
              featureId,
              enabled: !state.featuresState.features.find((f) => f.id === featureId)
                ?.enabled,
            },
          });
        }
      });
    },
    [setState, state.featuresState.features]
  );

  const setCurrentPage = useCallback(
    (page: number) => {
      setState((currentState) => ({
        featuresState: {
          ...currentState.featuresState,
          currentPage: page,
        },
      }));
    },
    [setState]
  );

  return {
    featuresState: state.featuresState,
    toggleFeature,
    setCurrentPage,
  };
}

export function useCSSScratchpad() {
  const [state, setState] = useAppStore();

  const updateDomainCSS = useCallback(
    (domain: string, css: string) => {
      setState((currentState) => ({
        cssScratchpadState: {
          domains: {
            ...currentState.cssScratchpadState.domains,
            [domain]: {
              css,
              enabled: currentState.cssScratchpadState.domains[domain]?.enabled ?? true,
              lastModified: Date.now(),
            },
          },
        },
      }));
    },
    [setState]
  );

  const toggleDomainCSS = useCallback(
    (domain: string) => {
      setState((currentState) => {
        const domainData = currentState.cssScratchpadState.domains[domain];
        if (!domainData) return {};

        return {
          cssScratchpadState: {
            domains: {
              ...currentState.cssScratchpadState.domains,
              [domain]: {
                ...domainData,
                enabled: !domainData.enabled,
              },
            },
          },
        };
      });
    },
    [setState]
  );

  const getDomainCSS = useCallback(
    (domain: string) => {
      return state.cssScratchpadState.domains[domain];
    },
    [state.cssScratchpadState.domains]
  );

  return {
    cssScratchpadState: state.cssScratchpadState,
    updateDomainCSS,
    toggleDomainCSS,
    getDomainCSS,
  };
}

export function useLiveCSS() {
  const [state, setState] = useAppStore();

  const setInput = useCallback(
    (input: string) => {
      setState((currentState) => ({
        liveCSSState: {
          ...currentState.liveCSSState,
          input,
        },
      }));
    },
    [setState]
  );

  const setCurrentDomain = useCallback(
    (domain: string | null) => {
      setState((currentState) => ({
        liveCSSState: {
          ...currentState.liveCSSState,
          currentDomain: domain,
        },
      }));
    },
    [setState]
  );

  const setInjected = useCallback(
    (injected: boolean) => {
      setState((currentState) => ({
        liveCSSState: {
          ...currentState.liveCSSState,
          isInjected: injected,
        },
      }));
    },
    [setState]
  );

  const clearAll = useCallback(() => {
    setState((currentState) => ({
      liveCSSState: {
        input: '',
        currentDomain: currentState.liveCSSState.currentDomain,
        isInjected: false,
      },
    }));
  }, [setState]);

  return {
    liveCSSState: state.liveCSSState,
    setInput,
    setCurrentDomain,
    setInjected,
    clearAll,
  };
}
