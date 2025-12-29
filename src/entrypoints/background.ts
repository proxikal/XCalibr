import { defineBackground } from 'wxt/sandbox';
import { updateState } from '../shared/state';

export default defineBackground(() => {
  chrome.commands.onCommand.addListener(async (command) => {
    if (command !== 'toggle-xcalibr-visibility') return;
    await updateState((current) => ({
      ...current,
      isVisible: !current.isVisible
    }));
  });
});
