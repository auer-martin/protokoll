import { compareVersions } from 'compare-versions'
import type { MDoc } from './model/mdoc.js'

import { calculateDeviceAutenticationBytes } from './utils.js'

import type { VerificationAssessment, VerificationCallback } from './check-callback.js'
import { defaultCallback, onCatCheck } from './check-callback.js'

import type { JWK } from 'jose'
import type { MdocContext, X509Context } from '../c-mdoc.js'
import { COSEKey, COSEKeyToRAW } from '../cose/key/cose-key.js'
import { Sign1 } from '../cose/sign1.js'
import { MDL_NAMESPACE } from './issuer-signed-item.js'
import { DeviceSignedDocument } from './model/device-signed-document.js'
import type IssuerAuth from './model/issuer-auth.js'
import type { IssuerSignedDocument } from './model/issuer-signed-document.js'
import type { DiagnosticInformation } from './model/types.js'
import { parseDeviceResponse } from './parser.js'

const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as Record<string, string>

export class Verifier {
  /**
   *
   * @param input.trustedCertificates The IACA root certificates list of the supported issuers.
   */
  public async verifyIssuerSignature(
    input: {
      trustedCertificates: Uint8Array[]
      issuerAuth: IssuerAuth
      now?: Date
      disableCertificateChainValidation: boolean
      onCheckG?: VerificationCallback
    },
    ctx: { x509: X509Context; cose: MdocContext['cose'] }
  ) {
    const { issuerAuth, disableCertificateChainValidation, onCheckG } = input
    const onCheck = onCatCheck(onCheckG ?? defaultCallback, 'ISSUER_AUTH')
    const { certificateChain } = issuerAuth
    const countryName = issuerAuth.getIssuingCountry(ctx)

    if (!certificateChain) {
      onCheck({
        status: 'FAILED',
        check: 'Missing x509 certificate in issuerAuth',
      })

      return
    }

    if (!issuerAuth.algName) {
      onCheck({
        status: 'FAILED',
        check: 'IssuerAuth must have an alg property',
      })

      return
    }

    if (!disableCertificateChainValidation) {
      const trustedCertificates = input.trustedCertificates
      try {
        if (!trustedCertificates[0]) {
          throw new Error('No trusted certificates found. Cannot verify issuer signature.')
        }
        await ctx.x509.validateCertificateChain({
          trustedCertificates: trustedCertificates as [Uint8Array, ...Uint8Array[]],
          x5chain: certificateChain,
        })
        onCheck({
          status: 'PASSED',
          check: 'Issuer certificate must be valid',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Issuer certificate must be valid',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }

    const verificationJwk = await ctx.x509.getPublicKey({
      certificate: issuerAuth.certificate,
      alg: issuerAuth.algName,
    })

    const verificationResult = await ctx.cose.sign1.verify({
      sign1: issuerAuth,
      jwk: verificationJwk,
    })

    onCheck({
      status: verificationResult ? 'PASSED' : 'FAILED',
      check: 'Issuer signature must be valid',
    })

    // Validity
    const { validityInfo } = issuerAuth.decodedPayload
    const now = input.now ?? new Date()

    const certificateData = await ctx.x509.getCertificateData({
      certificate: issuerAuth.certificate,
    })

    onCheck({
      status:
        validityInfo.signed < certificateData.notBefore || validityInfo.signed > certificateData.notAfter
          ? 'FAILED'
          : 'PASSED',
      check: 'The MSO signed date must be within the validity period of the certificate',
      reason: `The MSO signed date (${validityInfo.signed.toUTCString()}) must be within the validity period of the certificate (${certificateData.notBefore.toUTCString()} to ${certificateData.notAfter.toUTCString()})`,
    })

    onCheck({
      status: now < validityInfo.validFrom || now > validityInfo.validUntil ? 'FAILED' : 'PASSED',
      check: 'The MSO must be valid at the time of verification',
      reason: `The MSO must be valid at the time of verification (${now.toUTCString()})`,
    })

    onCheck({
      status: countryName ? 'PASSED' : 'FAILED',
      check: "Country name (C) must be present in the issuer certificate's subject distinguished name",
    })
  }

  public async verifyDeviceSignature(
    input: {
      deviceSigned: DeviceSignedDocument
      ephemeralPrivateKey?: JWK | Uint8Array
      sessionTranscriptBytes?: Uint8Array
      onCheckG?: VerificationCallback
    },
    ctx: {
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ) {
    const { deviceSigned, sessionTranscriptBytes, ephemeralPrivateKey } = input
    const onCheck = onCatCheck(input.onCheckG ?? defaultCallback, 'DEVICE_AUTH')

    const { deviceAuth, nameSpaces } = deviceSigned.deviceSigned
    const { docType } = deviceSigned
    const { deviceKeyInfo } = deviceSigned.issuerSigned.issuerAuth.decodedPayload
    const { deviceKey: deviceKeyCoseKey } = deviceKeyInfo ?? {}

    // Prevent cloning of the mdoc and mitigate man in the middle attacks
    if (!deviceAuth.deviceMac && !deviceAuth.deviceSignature) {
      onCheck({
        status: 'FAILED',
        check: 'Device Auth must contain a deviceSignature or deviceMac element',
      })
      return
    }

    if (!sessionTranscriptBytes) {
      onCheck({
        status: 'FAILED',
        check: 'Session Transcript Bytes missing from options, aborting device signature check',
      })
      return
    }

    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(sessionTranscriptBytes, docType, nameSpaces)

    if (!deviceKeyCoseKey) {
      onCheck({
        status: 'FAILED',
        check: 'Issuer signature must contain the device key.',
        reason: 'Unable to verify deviceAuth signature: missing device key in issuerAuth',
      })
      return
    }

    if (deviceAuth.deviceSignature) {
      const deviceKey = COSEKey.import(deviceKeyCoseKey)

      // ECDSA/EdDSA authentication
      try {
        const ds = deviceAuth.deviceSignature

        const sign1 = new Sign1(ds.protectedHeaders, ds.unprotectedHeaders, deviceAuthenticationBytes, ds.signature)

        const jwk = deviceKey.toJWK()
        const verificationResult = await ctx.cose.sign1.verify({ sign1, jwk })

        onCheck({
          status: verificationResult ? 'PASSED' : 'FAILED',
          check: 'Device signature must be valid',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Device signature must be valid',
          reason: `Unable to verify deviceAuth signature (ECDSA/EdDSA): ${err instanceof Error ? err.message : 'Unknown error'}`,
        })
      }
      return
    }

    // MAC authentication
    onCheck({
      status: deviceAuth.deviceMac ? 'PASSED' : 'FAILED',
      check: 'Device MAC must be present when using MAC authentication',
    })
    if (!deviceAuth.deviceMac) {
      return
    }

    onCheck({
      status: deviceAuth.deviceMac.hasSupportedAlg() ? 'PASSED' : 'FAILED',
      check: 'Device MAC must use alg 5 (HMAC 256/256)',
    })
    if (!deviceAuth.deviceMac.hasSupportedAlg()) {
      return
    }

    onCheck({
      status: ephemeralPrivateKey ? 'PASSED' : 'FAILED',
      check: 'Ephemeral private key must be present when using MAC authentication',
    })
    if (!ephemeralPrivateKey) {
      return
    }

    try {
      const deviceKeyRaw = COSEKeyToRAW(deviceKeyCoseKey)
      const ephemeralMacKeyJwk = await ctx.crypto.calculateEphemeralMacKeyJwk({
        privateKey:
          ephemeralPrivateKey instanceof Uint8Array
            ? ephemeralPrivateKey
            : COSEKeyToRAW(COSEKey.fromJWK(ephemeralPrivateKey).encode()),
        publicKey: deviceKeyRaw,
        sessionTranscriptBytes: sessionTranscriptBytes,
      })

      const isValid = await ctx.cose.mac0.verify({
        mac0: deviceAuth.deviceMac,
        jwk: ephemeralMacKeyJwk,
        options: { detachedPayload: deviceAuthenticationBytes },
      })

      onCheck({
        status: isValid ? 'PASSED' : 'FAILED',
        check: 'Device MAC must be valid',
      })
    } catch (err) {
      onCheck({
        status: 'FAILED',
        check: 'Device MAC must be valid',
        reason: `Unable to verify deviceAuth MAC: ${err instanceof Error ? err.message : 'Unknown error'}`,
      })
    }
  }

  public async verifyData(
    input: {
      mdoc: IssuerSignedDocument
      onCheckG?: VerificationCallback
    },
    ctx: { x509: X509Context; crypto: MdocContext['crypto'] }
  ) {
    const { mdoc, onCheckG } = input
    // Confirm that the mdoc data has not changed since issuance
    const { issuerAuth } = mdoc.issuerSigned
    const { valueDigests, digestAlgorithm } = issuerAuth.decodedPayload

    const onCheck = onCatCheck(onCheckG ?? defaultCallback, 'DATA_INTEGRITY')

    onCheck({
      status: digestAlgorithm && DIGEST_ALGS[digestAlgorithm] ? 'PASSED' : 'FAILED',
      check: 'Issuer Auth must include a supported digestAlgorithm element',
    })

    const nameSpaces = mdoc.issuerSigned.nameSpaces ?? {}

    await Promise.all(
      Array.from(nameSpaces.entries()).map(async ([ns, nsItems]) => {
        onCheck({
          status: valueDigests?.has(ns) ? 'PASSED' : 'FAILED',
          check: `Issuer Auth must include digests for namespace: ${ns}`,
        })

        const verifications = await Promise.all(
          nsItems.map(async (ev) => {
            const isValid = await ev.isValid(ns, issuerAuth, ctx)
            return { ev, ns, isValid }
          })
        )

        verifications
          .filter((v) => v.isValid)
          .forEach((v) => {
            onCheck({
              status: 'PASSED',
              check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
            })
          })

        verifications
          .filter((v) => !v.isValid)
          .forEach((v) => {
            onCheck({
              status: 'FAILED',
              check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
            })
          })

        if (ns === MDL_NAMESPACE) {
          const certificateData = await ctx.x509.getCertificateData({
            certificate: issuerAuth.certificate,
          })
          if (!certificateData.issuerName) {
            onCheck({
              status: 'FAILED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason:
                "The 'issuing_country' and 'issuing_jurisdiction' cannot be verified because the DS certificate was not provided",
            })
          } else {
            const invalidCountry = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_country')
              .find((v) => !v.isValid || !v.ev.matchCertificate(ns, issuerAuth, ctx))

            onCheck({
              status: invalidCountry ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason: invalidCountry
                ? // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
                  `The 'issuing_country' (${invalidCountry.ev.elementValue}) must match the 'countryName' (${issuerAuth.getIssuingCountry(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })

            const invalidJurisdiction = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
              .find((v) => !v.isValid || !v.ev.matchCertificate(ns, issuerAuth, ctx))

            onCheck({
              status: invalidJurisdiction ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
              reason: invalidJurisdiction
                ? // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
                  `The 'issuing_jurisdiction' (${invalidJurisdiction.ev.elementValue}) must match the 'stateOrProvinceName' (${issuerAuth.getIssuingStateOrProvince(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })
          }
        }
      })
    )
  }

  /**
   * Parse and validate a DeviceResponse as specified in ISO/IEC 18013-5 (Device Retrieval section).
   *
   * @param input.encodedDeviceResponse
   * @param input.encodedSessionTranscript The CBOR encoded SessionTranscript.
   * @param input.ephemeralReaderKey The private part of the ephemeral key used in the session where the DeviceResponse was obtained. This is only required if the DeviceResponse is using the MAC method for device authentication.
   */
  async verifyDeviceResponse(
    input: {
      encodedDeviceResponse: Uint8Array
      encodedSessionTranscript?: Uint8Array
      ephemeralReaderKey?: JWK | Uint8Array
      disableCertificateChainValidation?: boolean
      trustedCertificates: Uint8Array[]
      now?: Date
      onCheck?: VerificationCallback
    },
    ctx: {
      x509: X509Context
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ): Promise<MDoc> {
    const { encodedDeviceResponse, now, trustedCertificates } = input
    const onCheck = input.onCheck ?? defaultCallback

    const dr = parseDeviceResponse(encodedDeviceResponse)

    onCheck({
      status: dr.version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    })

    onCheck({
      status: compareVersions(dr.version, '1.0') >= 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response version must be 1.0 or greater',
      category: 'DOCUMENT_FORMAT',
    })

    onCheck({
      status: dr.documents.length > 0 ? 'PASSED' : 'FAILED',
      check: 'Device Response must include at least one document.',
      category: 'DOCUMENT_FORMAT',
    })

    for (const document of dr.documents) {
      const { issuerAuth } = document.issuerSigned
      if (!(document instanceof DeviceSignedDocument)) {
        onCheck({
          status: 'FAILED',
          category: 'DEVICE_AUTH',
          check: `The document is not signed by the device. ${document.docType}`,
        })
        continue
      }

      await this.verifyIssuerSignature(
        {
          issuerAuth,
          disableCertificateChainValidation: input.disableCertificateChainValidation ?? false,
          now,
          onCheckG: onCheck,
          trustedCertificates,
        },
        ctx
      )

      await this.verifyDeviceSignature(
        {
          deviceSigned: document,
          ephemeralPrivateKey: input.ephemeralReaderKey,
          sessionTranscriptBytes: input.encodedSessionTranscript,
          onCheckG: onCheck,
        },
        ctx
      )

      await this.verifyData({ mdoc: document, onCheckG: onCheck }, ctx)
    }

    return dr
  }

  async getDiagnosticInformation(
    encodedDeviceResponse: Uint8Array,
    options: {
      trustedCertificates: Uint8Array[]
      encodedSessionTranscript?: Uint8Array
      ephemeralReaderKey?: JWK | Uint8Array
      disableCertificateChainValidation?: boolean
    },
    ctx: {
      x509: X509Context
      crypto: MdocContext['crypto']
      cose: MdocContext['cose']
    }
  ): Promise<DiagnosticInformation> {
    const { trustedCertificates } = options
    const dr: VerificationAssessment[] = []
    const decoded = await this.verifyDeviceResponse(
      {
        encodedDeviceResponse,
        ...options,
        onCheck: (check) => dr.push(check),
        trustedCertificates,
      },
      ctx
    )

    const document = decoded.documents[0]
    if (!document) {
      throw new Error('No documents found for getting diagnostic information.')
    }

    const { issuerAuth } = document.issuerSigned
    const issuerCert = issuerAuth.certificate

    const attributes = (
      await Promise.all(
        Array.from(document.issuerSigned.nameSpaces.keys()).map(async (ns) => {
          const items = document.issuerSigned.nameSpaces.get(ns) ?? []
          return Promise.all(
            items.map(async (item) => {
              const isValid = await item.isValid(ns, issuerAuth, ctx)
              return {
                ns,
                id: item.elementIdentifier,
                value: item.elementValue,
                isValid,
                matchCertificate: item.matchCertificate(ns, issuerAuth, ctx),
              }
            })
          )
        })
      )
    ).flat()

    const deviceAttributes =
      document instanceof DeviceSignedDocument
        ? Array.from(document.deviceSigned.nameSpaces.entries()).flatMap(([ns, items]) => {
            return Array.from(items.entries()).map(([id, value]) => {
              return {
                ns,
                id,
                value,
              }
            })
          })
        : undefined

    let deviceKey: JWK | undefined = undefined

    if (document.issuerSigned.issuerAuth) {
      const { deviceKeyInfo } = document.issuerSigned.issuerAuth.decodedPayload
      if (deviceKeyInfo?.deviceKey) {
        deviceKey = COSEKey.import(deviceKeyInfo.deviceKey).toJWK()
      }
    }
    const disclosedAttributes = attributes.filter((attr) => attr.isValid).length
    const totalAttributes = Array.from(
      document.issuerSigned.issuerAuth.decodedPayload.valueDigests?.entries() ?? []
    ).reduce((prev, [, digests]) => prev + digests.size, 0)

    return {
      general: {
        version: decoded.version,
        type: 'DeviceResponse',
        status: decoded.status,
        documents: decoded.documents.length,
      },
      validityInfo: document.issuerSigned.issuerAuth.decodedPayload.validityInfo,
      issuerCertificate: await ctx.x509.getCertificateData({
        certificate: issuerCert,
      }),
      issuerSignature: {
        // TODO
        // biome-ignore lint/style/noNonNullAssertion: <explanation>
        alg: document.issuerSigned.issuerAuth.algName!,
        isValid: dr.filter((check) => check.category === 'ISSUER_AUTH').every((check) => check.status === 'PASSED'),
        reasons: dr
          .filter((check) => check.category === 'ISSUER_AUTH' && check.status === 'FAILED')
          .map((check) => check.reason ?? check.check),
        digests: Object.fromEntries(
          Array.from(document.issuerSigned.issuerAuth.decodedPayload.valueDigests?.entries() ?? []).map(
            ([ns, digests]) => [ns, digests.size]
          )
        ),
      },
      deviceKey: {
        jwk: deviceKey,
      },
      deviceSignature:
        document instanceof DeviceSignedDocument
          ? {
              alg:
                document.deviceSigned.deviceAuth.deviceSignature?.algName ??
                document.deviceSigned.deviceAuth.deviceMac?.algName,
              isValid: dr
                .filter((check) => check.category === 'DEVICE_AUTH')
                .every((check) => check.status === 'PASSED'),
              reasons: dr
                .filter((check) => check.category === 'DEVICE_AUTH' && check.status === 'FAILED')
                .map((check) => check.reason ?? check.check),
            }
          : undefined,
      dataIntegrity: {
        disclosedAttributes: `${disclosedAttributes} of ${totalAttributes}`,
        isValid: dr.filter((check) => check.category === 'DATA_INTEGRITY').every((check) => check.status === 'PASSED'),
        reasons: dr
          .filter((check) => check.category === 'DATA_INTEGRITY' && check.status === 'FAILED')
          .map((check) => check.reason ?? check.check),
      },
      attributes,
      deviceAttributes,
      // TODO!!!!
      // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    } as any
  }
}
