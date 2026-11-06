import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { UpdateBanner } from './Updates';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <UpdateBanner />
    <App />
  </StrictMode>,
);
