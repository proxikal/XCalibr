import { defineConfig } from 'wxt';

export default defineConfig({
  srcDir: 'src',
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'XCalibr',
    description: 'Embeds a persistent tool menu into every page you visit.',
    permissions: ['storage', 'tabs', 'scripting'],
    host_permissions: ['<all_urls>'],
    commands: {
      'toggle-xcalibr-visibility': {
        suggested_key: {
          default: 'Ctrl+Shift+V',
          mac: 'Command+Shift+V'
        },
        description: 'Toggle XCalibr visibility'
      }
    },
    action: {
      default_title: 'XCalibr',
      default_popup: 'popup.html'
    }
  }
});
