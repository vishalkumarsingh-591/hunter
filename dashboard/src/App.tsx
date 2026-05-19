import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import NewScan from "./pages/NewScan";
import ScanDetail from "./pages/ScanDetail";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="scan/new" element={<NewScan />} />
        <Route path="scan/:scanId" element={<ScanDetail />} />
      </Route>
    </Routes>
  );
}
