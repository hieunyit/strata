import '@testing-library/jest-dom';

// jsdom has no canvas; ECharts only measures text with it.
HTMLCanvasElement.prototype.getContext = (() => null) as unknown as HTMLCanvasElement['getContext'];
