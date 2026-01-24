import { PAYMASTER_URL } from "./config";

export const isGasSponsorshipChain = (chainId: number) => {
  return PAYMASTER_URL[chainId] !== undefined && PAYMASTER_URL[chainId] !== "";
};
