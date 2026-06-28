import { Header } from './components/Header';
import { Hero } from './components/Hero';
import { ToolkitGrid } from './components/ToolkitGrid';
import { HowItWorks } from './components/HowItWorks';
import { TestDataSources } from './components/TestDataSources';
import { Footer } from './components/Footer';

export function App() {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <main className="flex-1">
        <Hero />
        <ToolkitGrid />
        <HowItWorks />
        <TestDataSources />
      </main>
      <Footer />
    </div>
  );
}
