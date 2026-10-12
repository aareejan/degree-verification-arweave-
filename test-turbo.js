const { TurboFactory } = require("@ardrive/turbo-sdk");

const turbo = TurboFactory.unauthenticated({
  token: "base-usdc"
});

console.log("Upload service:");
console.dir(turbo.uploadService, { depth: null });

console.log("\nMethods:");
console.log(Object.getOwnPropertyNames(Object.getPrototypeOf(turbo.uploadService)).sort());