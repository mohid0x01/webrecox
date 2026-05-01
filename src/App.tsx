import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Analytics } from "@vercel/analytics/react";
import Index from "./pages/Index.tsx";
import Oneliners from "./pages/Oneliners.tsx";
import NotFound from "./pages/NotFound.tsx";
import FloatingPortfolio from "./components/FloatingPortfolio.tsx";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/oneliners" element={<Oneliners />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
        <FloatingPortfolio />
      </BrowserRouter>
      <Analytics />
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
