const path = require('path');

module.exports = {
  mode: 'production', // Use production mode for minification
  entry: './highlight-setup.js',
  output: {
    filename: 'highlight.bundle.min.js',
    path: path.resolve(__dirname, './app/static/js'),
  },

};
