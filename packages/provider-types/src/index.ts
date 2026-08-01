export interface ProviderCapabilities { streaming:boolean; structuredOutput:boolean; toolRequests:boolean; local:boolean }
export interface ProviderEvent { type:"status"|"text"|"usage"|"error"; payload:unknown }
