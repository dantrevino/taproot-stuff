import * as bitcoin from "bitcoinjs-lib";
import * as bip371 from "bitcoinjs-lib/src/psbt/bip371";
import BIP32Factory from "bip32";
import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";
import { BITCOIN_NETWORK, FEES } from "../config";
import { CONVERTERS } from "../src/utils/constants";
const minRelay = FEES[BITCOIN_NETWORK] * CONVERTERS.SATOSHI;
const fee = minRelay * CONVERTERS.SATOSHI;

const network = bitcoin.networks[BITCOIN_NETWORK];
const bip32 = BIP32Factory(ecc);
const ECPair = ECPairFactory(ecc);

const key = {
  generator:
    "4df812724dc1dac6da6020bf0ce77c6874a99a5775d701fac6c36a426096058474771ab40a5ef328d3179a2bccba02d2cdb4f7ecc6330677079ede09ee59f7d2",
  privateKey:
    "e2139993570ff137dbd6219ab9d405d06ed41c558f23010f1cacdc549852d902",
  publicKey:
    "0388ce262cedec3709a9bd63b4d06ae588d70579d62a3ad884c322af8de7913500",
  wif: "cVAAX6QymyeaWRVCTc93LxYX1yPoPvvKW5x7FtFwzhnBxWmMwa1J",
};
const wifs = {
  oracle: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
  lender: "KxhEDBQyyEFymvfJD96q8stMbJMbZUb6D1PmXqBWZDU2WvbvVs9o",
  borrower: "KzrA86mCVMGWnLGBQu9yzQa32qbxb5dvSK4XhyjjGAWSBKYX4rHx",
};

const keypairs = {
  oracle: ECPair.fromWIF(wifs.oracle),
  lender: ECPair.fromWIF(wifs.lender),
  borrower: ECPair.fromWIF(wifs.borrower),
};

const toXOnly = (pubKey) =>
  pubKey.length === 32 ? pubKey : pubKey.slice(1, 33);

function tweakSigner(signer: bitcoin.Signer, opts: any = {}): bitcoin.Signer {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  let privateKey: Uint8Array | undefined = signer.privateKey!;
  if (!privateKey) {
    throw new Error("Private key is required for tweaking signer!");
  }
  if (signer.publicKey[0] === 3) {
    privateKey = ecc.privateNegate(privateKey);
  }

  const tweakedPrivateKey = ecc.privateAdd(
    privateKey,
    tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash)
  );
  if (!tweakedPrivateKey) {
    throw new Error("Invalid tweaked private key!");
  }

  return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
    network: opts.network,
  });
}

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
  return bitcoin.crypto.taggedHash(
    "TapTweak",
    Buffer.concat(h ? [pubKey, h] : [pubKey])
  );
}

const txId = "41d86bb415de1b1c512012e83a5fa7bf7947a2b0f7f695ceebaed466c1ee9759";
const msigValue = 98689;
const ordinals = {
  exi: async ({ container }) => {
    const txId =
      "d55b50bb75ba13d76715a0ee417801d616eb17db031f7bfe85a9d221f04e44fd";
    const internalKey = bip32.fromSeed(
      Buffer.from(key.generator, "hex"),
      network
    );
    const leafScriptAsm = `${keypairs.borrower.publicKey.toString(
      "hex"
    )} OP_CHECKSIG`;
    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree = [
      {
        output: leafScript,
      },
      {
        output: leafScript,
      },
    ];
    const redeem = {
      output: leafScript,
      redeemVersion: 192,
    };

    const { output, witness, address } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      scriptTree,
      redeem,
      network,
    });
    console.log("address :>> ", address);
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: txId,
      index: 0,
      witnessUtxo: {
        value: 1000,
        script: Buffer.from(
          "512075ddf50825942329964b43b4115fceb4644a25eb1041881c3479748bfc11d2d7",
          "hex"
        ),
      },
    });
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: redeem.redeemVersion,
          script: redeem.output,
          controlBlock: witness![witness!.length - 1],
        },
      ],
    });
    psbt.addOutput({
      value: 1000 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    psbt.signInput(0, keypairs.borrower);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
  exs: async ({ container }) => {
    // Spend MSIG
    const internalKey = ECPair.fromWIF(key.wif, network);
    const leafScriptAsm = `${toXOnly(keypairs.borrower.publicKey).toString(
      "hex"
    )} OP_CHECKSIG ${toXOnly(keypairs.oracle.publicKey).toString(
      "hex"
    )} OP_CHECKSIGADD OP_2 OP_NUMEQUAL`;

    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree = {
      output: leafScript,
    };
    const redeem = {
      output: leafScript,
      redeemVersion: 192,
    };

    const { witness, address } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      scriptTree,
      redeem,
      network,
    });
    console.log("address :>> ", address);
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: txId,
      index: 0,
      witnessUtxo: {
        value: 10000,
        script: Buffer.from(
          "512017678d72c53fcd9df10e6e24dbfcb375466f284e29ad88d61514060a597edced",
          "hex"
        ),
      },
    });
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: redeem.redeemVersion,
          script: redeem.output,
          controlBlock: witness![witness!.length - 1],
        },
      ],
    });

    psbt.addOutput({
      value: 10000 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    psbt.signInput(0, keypairs.borrower);
    psbt.signInput(0, keypairs.oracle);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
  exm: async ({ container }) => {
    // MSIG
    const internalKey = ECPair.fromWIF(key.wif, network);
    const leafScriptAsm = `${toXOnly(keypairs.borrower.publicKey).toString(
      "hex"
    )} OP_CHECKSIG ${toXOnly(keypairs.oracle.publicKey).toString(
      "hex"
    )} OP_CHECKSIGADD OP_2 OP_NUMEQUAL`;

    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree = {
      output: leafScript,
    };
    const redeem = {
      output: leafScript,
      redeemVersion: 192,
    };

    const { address } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      scriptTree,
      redeem,
      network,
    });
    console.log("address ex :>> ", address);
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: txId,
      index: 1,
      witnessUtxo: {
        value: msigValue,
        script: Buffer.from(
          "512055ba1a6e09ed8d09a7b823a61d01c108bafc06caaaa361af36bb73639e096817",
          "hex"
        ),
      },
      tapInternalKey: Buffer.from(
        "1527224d68008a5b8f8c04ffc10cb7f347d0374cb2fd4357f30c4b27afe89bc8",
        "hex"
      ),
    });

    psbt.addOutput({
      value: 10000,
      address,
      tapInternalKey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      tapTree: { leaves: bip371.tapTreeToList(scriptTree) },
    });

    psbt.addOutput({
      value: msigValue - 10000 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    return psbt.toBase64();
  },
  ex: async ({ container }) => {
    // Decode MSIG
    const raw =
      "cHNidP8BAKcCAAAAAgabyekpeShsbBvrBNvLoZvmqMBKa0WpVRgcLFYUg/CIAAAAAAD/////tQlJHpLE0Nb4LFhv8UTcMctlvcTh8+ux+a7/Czxzs9UCAAAAAP////8C2SUAAAAAAAAiUSAnPcOrF728HRNczYJk0UqmXmy+DAvBKCb9/T3sE9Ca9EgoEAAAAAAAF6kUXXEwFMAS3Pbn7RnX7YwEMa6ddsuHAAAAAAABASvZJQAAAAAAACJRIFW6Gm4J7Y0Jp7gjph0BwQi6/AbKqqNhrza7c2OeCWgXARNAqyRVBLFFq4WpYHBUiB+3zSfWtuMqU6NttpES8TnoqHA5SeztqDteUc4y3Fg01pvLDBHm9KZJ8H6LI6w/XSvjxgEXIBUnIk1oAIpbj4wE/8EMt/NH0DdMsv1DV/MMSyev6JvIAAEA/ZkBAgAAAAABAu111SUc+uRzo5xHDdIl2GoBNjBIUnP/5IvP4Vwn8gxUAAAAAAD/////7XXVJRz65HOjnEcN0iXYagE2MEhSc//ki8/hXCfyDFQBAAAAFxYAFA8ZpeZ9tAzNa80D9q/HXTQ0Vkyw/////wMQJwAAAAAAACJRIPGqCAadUuCByrbkRjgYHtXmRNtWWvL16iDQVJTBL1L6IKEHAAAAAAAiUSBVuhpuCe2NCae4I6YdAcEIuvwGyqqjYa82u3NjngloF1hPEAAAAAAAF6kUXXEwFMAS3Pbn7RnX7YwEMa6ddsuHAUBN2S+N97i603i1sF76YI36u/9cClfa38D6/hHN0Z8/AAePYSnjevWKuEYVfGlNbdHMSOtcivxOvQWpF/WXOGGDAkgwRQIhAJJGQl2ZzXxuZa9Bt/EjqYvRdlza1/28XEHjNKMauHu5AiALp+U5UDyBv8rXYXHYx8/ebWxrSnw3b9yNfZUR5O7/YQEhA9C8BO3efQ5RW9ZOAbASdbdgpJ97K7Xos609aCDqYyu9AAAAAAEBIFhPEAAAAAAAF6kUXXEwFMAS3Pbn7RnX7YwEMa6ddsuHIgID0LwE7d59DlFb1k4BsBJ1t2Ckn3srteizrT1oIOpjK71HMEQCIADpxK7EN2ws5JWwJ6nW+CxvOwWyvXP4PVTcenzTwIu9AiAoieYru12cP9p6CEpgc/iluzUBU55SPotZpTmqxyHzPgEBBBYAFA8ZpeZ9tAzNa80D9q/HXTQ0VkywAAEFIJNnR2bKo9ucD2PEt08wJRDFCdbQ/6ydZyFNjwPLLtJ6AQZJAMBGIBUnIk1oAIpbj4wE/8EMt/NH0DdMsv1DV/MMSyev6JvIrCDQvATt3n0OUVvWTgGwEnW3YKSfeyu16LOtPWgg6mMrvbpSnAAA";
    const psbt = bitcoin.Psbt.fromBase64(raw);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
};
const standard = {
  exi: async ({ container }) => {
    const txId =
      "d55b50bb75ba13d76715a0ee417801d616eb17db031f7bfe85a9d221f04e44fd";
    const internalKey = bip32.fromSeed(
      Buffer.from(key.generator, "hex"),
      network
    );
    const leafScriptAsm = `${keypairs.borrower.publicKey.toString(
      "hex"
    )} OP_CHECKSIG`;
    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree = [
      {
        output: leafScript,
      },
      {
        output: leafScript,
      },
    ];
    const redeem = {
      output: leafScript,
      redeemVersion: 192,
    };

    const { output, witness, address } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      scriptTree,
      redeem,
      network,
    });
    console.log("address :>> ", address);
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: txId,
      index: 0,
      witnessUtxo: {
        value: 1000,
        script: Buffer.from(
          "512075ddf50825942329964b43b4115fceb4644a25eb1041881c3479748bfc11d2d7",
          "hex"
        ),
      },
    });
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: redeem.redeemVersion,
          script: redeem.output,
          controlBlock: witness![witness!.length - 1],
        },
      ],
    });
    psbt.addOutput({
      value: 1000 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    psbt.signInput(0, keypairs.borrower);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
  exs: async ({ container }) => {
    // Spend MSIG
    const internalKey = ECPair.fromWIF(key.wif, network);
    const leafScriptAsm = `${toXOnly(keypairs.borrower.publicKey).toString(
      "hex"
    )} OP_CHECKSIG ${toXOnly(keypairs.oracle.publicKey).toString(
      "hex"
    )} OP_CHECKSIGADD OP_2 OP_NUMEQUAL`;

    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree = {
      output: leafScript,
    };
    const redeem = {
      output: leafScript,
      redeemVersion: 192,
    };

    const { witness, address } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      scriptTree,
      redeem,
      network,
    });
    console.log("address :>> ", address);
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: txId,
      index: 0,
      witnessUtxo: {
        value: 10000,
        script: Buffer.from(
          "512017678d72c53fcd9df10e6e24dbfcb375466f284e29ad88d61514060a597edced",
          "hex"
        ),
      },
    });
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: redeem.redeemVersion,
          script: redeem.output,
          controlBlock: witness![witness!.length - 1],
        },
      ],
    });

    psbt.addOutput({
      value: 10000 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    psbt.signInput(0, keypairs.borrower);
    psbt.signInput(0, keypairs.oracle);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
  exf: async ({ container }) => {
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: "9afc02f8616f5efd1e327a62ce88e355e04bd09971f571effd392dad632a04a4",
      index: 0,
      witnessUtxo: {
        value: 484134,
        script: Buffer.from(
          "512055ba1a6e09ed8d09a7b823a61d01c108bafc06caaaa361af36bb73639e096817",
          "hex"
        ),
      },
      tapInternalKey: Buffer.from(
        "1527224d68008a5b8f8c04ffc10cb7f347d0374cb2fd4357f30c4b27afe89bc8",
        "hex"
      ),
    });

    psbt.addOutput({
      value: 484134 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    return psbt.toBase64();
  },
  ex: async ({ container }) => {
    // Decode MSIG
    const raw =
      "cHNidP8BAKcCAAAAAswIz8hsfis0a9lg9Ssprhihnbdx3dakLtB/KBCFVTGHAAAAAAD/////fIoOPN4lE2QX+gMyvY/vzsH3k3CDz9+NSi3CoyjiJ/QBAAAAAP////8CIKEHAAAAAAAiUSAnPcOrF728HRNczYJk0UqmXmy+DAvBKCb9/T3sE9Ca9D6GCAAAAAAAF6kUXXEwFMAS3Pbn7RnX7YwEMa6ddsuHAAAAAAABASsgoQcAAAAAACJRIFW6Gm4J7Y0Jp7gjph0BwQi6/AbKqqNhrza7c2OeCWgXARNA12oYu87FQK4St59ZsV+j4VfNgmqS3CsiXSMZv6bqClXbcsBHRhrQMX08TWJqMe+L/8q7ZKjDcm1ovqUP/yoDQwEXIBUnIk1oAIpbj4wE/8EMt/NH0DdMsv1DV/MMSyev6JvIAAEA/W0BAgAAAAABAgabyekpeShsbBvrBNvLoZvmqMBKa0WpVRgcLFYUg/CIAAAAAAD/////tQlJHpLE0Nb4LFhv8UTcMctlvcTh8+ux+a7/Czxzs9UCAAAAFxYAFA8ZpeZ9tAzNa80D9q/HXTQ0Vkyw/////wLZJQAAAAAAACJRICc9w6sXvbwdE1zNgmTRSqZebL4MC8EoJv39PewT0Jr0SCgQAAAAAAAXqRRdcTAUwBLc9uftGdftjAQxrp12y4cBQKskVQSxRauFqWBwVIgft80n1rbjKlOjbbaREvE56KhwOUns7ag7XlHOMtxYNNabywwR5vSmSfB+iyOsP10r48YCRzBEAiAA6cSuxDdsLOSVsCep1vgsbzsFsr1z+D1U3Hp808CLvQIgKInmK7tdnD/aeghKYHP4pbs1AVOeUj6LWaU5qsch8z4BIQPQvATt3n0OUVvWTgGwEnW3YKSfeyu16LOtPWgg6mMrvQAAAAABASBIKBAAAAAAABepFF1xMBTAEtz25+0Z1+2MBDGunXbLhyICA9C8BO3efQ5RW9ZOAbASdbdgpJ97K7Xos609aCDqYyu9SDBFAiEAli+7RZpkzkRBg3dbGDMpOkh8bgp+PXA7P6RrYvnxhU8CIC/SajtqrqoILhs8cdddMKhM0P867uXeT1rsZLKc+Z90AQEEFgAUDxml5n20DM1rzQP2r8ddNDRWTLAAAQUgk2dHZsqj25wPY8S3TzAlEMUJ1tD/rJ1nIU2PA8su0noBBkkAwEYgFSciTWgAiluPjAT/wQy380fQN0yy/UNX8wxLJ6/om8isINC8BO3efQ5RW9ZOAbASdbdgpJ97K7Xos609aCDqYyu9ulKcAAA=";
    const psbt = bitcoin.Psbt.fromBase64(raw);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
};

//tb1pmlppgnhapuwvn5jz89w838d0xhc7kk85au0nq8w5sxurps252skqeqruz8
//const leafScriptAsm = `${leafPubkeys[2]} OP_CHECKSIG ${leafPubkeys[1]} OP_CHECKSIGADD ${leafPubkeys[0]} OP_CHECKSIGADD OP_3 OP_NUMEQUAL`;

export default {
  exi: async ({ container }) => {
    const txId =
      "d55b50bb75ba13d76715a0ee417801d616eb17db031f7bfe85a9d221f04e44fd";
    const internalKey = bip32.fromSeed(
      Buffer.from(key.generator, "hex"),
      network
    );
    const leafScriptAsm = `${keypairs.borrower.publicKey.toString(
      "hex"
    )} OP_CHECKSIG`;
    const leafScript = bitcoin.script.fromASM(leafScriptAsm);

    const scriptTree = [
      {
        output: leafScript,
      },
      {
        output: leafScript,
      },
    ];
    const redeem = {
      output: leafScript,
      redeemVersion: 192,
    };

    const { output, witness, address } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      scriptTree,
      redeem,
      network,
    });
    console.log("address :>> ", address);
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: txId,
      index: 0,
      witnessUtxo: {
        value: 1000,
        script: Buffer.from(
          "512075ddf50825942329964b43b4115fceb4644a25eb1041881c3479748bfc11d2d7",
          "hex"
        ),
      },
    });
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: redeem.redeemVersion,
          script: redeem.output,
          controlBlock: witness![witness!.length - 1],
        },
      ],
    });
    psbt.addOutput({
      value: 1000 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    psbt.signInput(0, keypairs.borrower);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
  ex: async ({ container }) => {
    // Spend MSIG
    const internalKey = ECPair.fromWIF(key.wif, network);
    const paths = [
      [keypairs.borrower.publicKey, keypairs.oracle.publicKey],
      [keypairs.lender.publicKey, keypairs.oracle.publicKey],
    ];
    const leafScriptsAsm = [
      `${toXOnly(paths[0][0]).toString("hex")} OP_CHECKSIG ${toXOnly(
        paths[0][1]
      ).toString("hex")} OP_CHECKSIGADD OP_${2} OP_NUMEQUAL`,
      `${toXOnly(paths[1][0]).toString("hex")} OP_CHECKSIG ${toXOnly(
        paths[1][1]
      ).toString("hex")} OP_CHECKSIGADD OP_${2} OP_NUMEQUAL`,
    ];
    const leafScripts = leafScriptsAsm.map((leafScriptAsm) =>
      bitcoin.script.fromASM(leafScriptAsm)
    );
    const scriptTree = [
      {
        output: leafScripts[0],
      },
      {
        output: leafScripts[1],
      },
    ];

    const redeem = {
      output: leafScripts[0],
      redeemVersion: 192,
    };

    const { witness, address } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      scriptTree,
      redeem,
      network,
    });
    console.log("address :>> ", address);
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: txId,
      index: 0,
      witnessUtxo: {
        value: 1000,
        script: Buffer.from(
          "51208c4b4404dd7cbe88d816b53dfe9a2559ea2812914320c11fa302635a1f7a529f",
          "hex"
        ),
      },
    });
    psbt.updateInput(0, {
      tapLeafScript: [
        {
          leafVersion: redeem.redeemVersion,
          script: redeem.output,
          controlBlock: witness![witness!.length - 1],
        },
      ],
    });

    psbt.addOutput({
      value: 1000 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    psbt.signInput(0, keypairs.borrower);
    psbt.signInput(0, keypairs.oracle);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
  exm: async ({ container }) => {
    // MSIG
    const internalKey = ECPair.fromWIF(key.wif, network);
    const paths = [
      [keypairs.borrower.publicKey, keypairs.oracle.publicKey],
      [keypairs.lender.publicKey, keypairs.oracle.publicKey],
    ];
    const leafScriptsAsm = [
      `${toXOnly(paths[0][0]).toString("hex")} OP_CHECKSIG ${toXOnly(
        paths[0][1]
      ).toString("hex")} OP_CHECKSIGADD OP_${2} OP_NUMEQUAL`,
      `${toXOnly(paths[1][0]).toString("hex")} OP_CHECKSIG ${toXOnly(
        paths[1][1]
      ).toString("hex")} OP_CHECKSIGADD OP_${2} OP_NUMEQUAL`,
    ];
    const leafScripts = leafScriptsAsm.map((leafScriptAsm) =>
      bitcoin.script.fromASM(leafScriptAsm)
    );
    const scriptTree = [
      {
        output: leafScripts[0],
      },
      {
        output: leafScripts[1],
      },
    ];
    /*const redeem = {
      output: leafScript,
      redeemVersion: 192,
    };*/

    const { address } = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      scriptTree,
      //redeem,
      network,
    });
    console.log("address ex :>> ", address);
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: txId,
      index: 1,
      witnessUtxo: {
        value: msigValue,
        script: Buffer.from(
          "512055ba1a6e09ed8d09a7b823a61d01c108bafc06caaaa361af36bb73639e096817",
          "hex"
        ),
      },
      tapInternalKey: Buffer.from(
        "1527224d68008a5b8f8c04ffc10cb7f347d0374cb2fd4357f30c4b27afe89bc8",
        "hex"
      ),
    });

    psbt.addOutput({
      value: 1000,
      address,
      tapInternalKey: toXOnly(internalKey.publicKey),
      //@ts-ignore
      tapTree: { leaves: bip371.tapTreeToList(scriptTree) },
    });

    psbt.addOutput({
      value: msigValue - 1000 - fee,
      address: "tb1p2kap5msfakxsnfacywnp6qwppza0cpk2423krtekhdek88sfdqtse2fkf0",
    });
    return psbt.toBase64();
  },
  exd: async ({ container }) => {
    // Decode MSIG
    const raw =
      "cHNidP8BAIkCAAAAAcw4aRBOvrgK0FUkhZy2rz1zH7cs5PkfVg+LMNO/PB3KAQAAAAD/////AugDAAAAAAAAIlEgjEtEBN18vojYFrU9/polWeooEpFDIMEfowJjWh96Up9ifAEAAAAAACJRIFW6Gm4J7Y0Jp7gjph0BwQi6/AbKqqNhrza7c2OeCWgXAAAAAAABASuBgQEAAAAAACJRIFW6Gm4J7Y0Jp7gjph0BwQi6/AbKqqNhrza7c2OeCWgXARNAGBcJaP5pvaulPhbeNCdczRCePb46FPE7rkqhuRCtPM7QnpgQDO8GOpEEaJ9rvS11Cby0/ecFt4fimWk0ZEmkPgEXIBUnIk1oAIpbj4wE/8EMt/NH0DdMsv1DV/MMSyev6JvIAAEFIIjOJizt7DcJqb1jtNBq5YjXBXnWKjrYhMMir43nkTUAAQaSAcBGIEKJgBNmvO5hcrdxz1p/E6rs0jeguaH/nXacq8Lmtwo0rCB5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmLpSnAHARiC4ABGog6D9YhrUbfxAXfHnS/B1y69wD9Suvvbpb4SDQKwgeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5i6UpwAAA==";
    const psbt = bitcoin.Psbt.fromBase64(raw);
    return psbt.finalizeAllInputs().extractTransaction().toHex();
  },
};