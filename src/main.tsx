import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./ui/App";
import { AuthGate } from "./ui/auth/Login";
import "./ui/styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthGate>{(session, signOut) => <App key={session.me.id} session={session} onSignOut={signOut} />}</AuthGate>
  </StrictMode>,
);
