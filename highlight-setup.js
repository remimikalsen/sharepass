// highlight-setup.js

// Import the core library
import hljs from 'highlight.js/lib/core';

// Import the languages you need
import json from 'highlight.js/lib/languages/json';
import yaml from 'highlight.js/lib/languages/yaml';

// Register the languages with highlight.js
hljs.registerLanguage('json', json);
hljs.registerLanguage('yaml', yaml);

// Expose hljs to the global window 
window.hljs = hljs;
