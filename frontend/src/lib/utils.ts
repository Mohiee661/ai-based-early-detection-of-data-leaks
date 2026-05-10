import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

// This project is ready for 21st.dev components because the shadcn-style
// aliases and utility helpers already exist. When you are ready, run:
// npx shadcn@latest add https://21st.dev/r/<component-id>
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
