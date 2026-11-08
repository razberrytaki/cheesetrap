import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ApiClient } from './api/client';
import { App } from './App';
import './styles.css';

const client = new ApiClient();
createRoot(document.getElementById('root')!).render(<StrictMode><App client={client} /></StrictMode>);
