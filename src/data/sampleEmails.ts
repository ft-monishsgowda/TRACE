export interface SampleEmail {
  id: string;
  name: string;
  category: 'threat' | 'moderate' | 'good';
  expectedScoreRange: [number, number];
  notes: string;
  content: string;
}

export const SAMPLE_EMAILS: SampleEmail[] = [
  {
    id: "threat_paypal_credential_phish",
    name: "paypal_phishing_sample.eml",
    category: "threat",
    expectedScoreRange: [90, 100],
    notes: "Exact reference case matching the 3-page forensic dossier PDF: Claimed paypal.com sender with mismatched Reply-To (paypal-verify-billing-notice.com), Return-Path divergence (attacker-relay.net), Tor exit node origin (185.220.101.5, Bucharest RO), SPF softfail, DKIM missing, DMARC fail, and phishing landing domain.",
    content: `From: "PayPal Security Team" <security@paypal.com>
To: victim@target-corp.com
Subject: URGENT: Your PayPal Account Has Been Suspended — Verify Identity Immediately
Message-ID: <178938738888.104.fd55be99@paypal.com>
Date: Sat, 12 Sep 2026 20:34:01 -0000
Reply-To: security-update@paypal-verify-billing-notice.com
Return-Path: <bounce@attacker-relay.net>
Received: from mx.google.com (mx.google.com [142.250.31.27]) by
 recipient-inbox.corp with ESMTPS id g91; Sat, 12 Sep 2026 20:34:01 +0000
Received: from smtp-out2.relay-forward.net (smtp-out2.relay-forward.net
 [45.155.205.18]) by mx.google.com with ESMTPS id r22; Sat, 12 Sep 2026 20:33:45
 +0000
Received: from mail.attacker-relay.net (mail.attacker-relay.net [185.220.101.5])
 by smtp-out2.relay-forward.net with ESMTP id at8; Sat, 12 Sep 2026 20:33:10 +0000
X-Originating-IP: [185.220.101.5]
Received-SPF: softfail (mx.google.com: domain of transitioning security@paypal.com
 does not designate 185.220.101.5 as permitted sender) client-ip=185.220.101.5
Authentication-Results: mx.google.com;
 spf=softfail (google.com: domain of transitioning security@paypal.com does not designate 185.220.101.5 as permitted sender);
 dkim=none (message not signed);
 dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
X-Spam-Status: Yes, score=9.8 required=5.0
 tests=SPF_SOFTFAIL,DKIM_MISSING,DMARC_FAIL,PAYPAL_SPOOF,PHISH_LANDING
X-Spam-Score: 9.8
X-Priority: 1 (Highest)
Importance: High
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear Customer,

We have detected unauthorized access attempts on your PayPal account. As a security measure, your account has been temporarily suspended.

Please verify your identity immediately to restore full account privileges:
https://paypal-security-update-verification.com/login

Failure to verify within 24 hours will result in permanent account termination.

PayPal Security Operations
`
  },
  {
    id: "threat_phishing_bank_alert",
    name: "threat_phishing_bank_alert.eml",
    category: "threat",
    expectedScoreRange: [85, 100],
    notes: "3-hop Received chain traces back to a low-trust dynamic IP relayed through a spam-hosting box (geolocation mismatch vs claimed bank); Received-SPF/Authentication-Results all fail; no DKIM signature at all; spam filter score flagged; urgency priority headers set.",
    content: `From: "SecureBank Support" <support@secure-bank-alert.test>
To: monish.k@example.com
Subject: URGENT: Your Account Will Be Suspended in 24 Hours
Message-ID: <178938738888.104.4837163728185661848@secure-bank-alert.test>
Date: Mon, 14 Sep 2026 12:01:08 -0000
Reply-To: verify-team@secure-bank-alert.test
Return-Path: <bounce@secure-bank-alert.test>
Received: from mx.example.com (mx.example.com [192.0.2.5]) by
 inbound-gw.example.com with ESMTPS id fh1a for <monish.k@example.com>; Mon,
 14 Sep 2026 12:03:08 -0000
Received: from relay-09.spam-hosting.test (relay-09.spam-hosting.test
 [198.51.100.201]) by mx.example.com with SMTP id gt7b; Mon, 14 Sep 2026
 12:02:08 -0000
Received: from unknown-host-203-0-113-77.dyn.isp-lowtrust.test (unknown
 [203.0.113.77]) by relay-09.spam-hosting.test with SMTP id aq2c
 (envelope-from <bounce@secure-bank-alert.test>); Mon, 14 Sep 2026 12:01:08
 -0000
X-Originating-IP: [203.0.113.77]
Received-SPF: fail (mx.example.com: domain of secure-bank-alert.test does not
 designate 203.0.113.77 as permitted sender) client-ip=203.0.113.77
Authentication-Results: mx.example.com; spf=fail (sender IP is 203.0.113.77)
 smtp.mailfrom=secure-bank-alert.test; dkim=none (message not signed);
 dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=secure-bank-alert.test
X-Spam-Status: Yes, score=8.4 required=5.0
 tests=SPF_FAIL,URI_PHISH,SUBJ_URGENT_ALERT,FREEMAIL_REPLYTO_MISMATCH
X-Spam-Score: 8.4
X-Priority: 1 (Highest)
Importance: High
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear Valued Customer,

We detected unusual sign-in activity on your SecureBank account from a
new device. For your protection, your account access has been LIMITED.

You must verify your identity within 24 hours or your account will be
permanently suspended.

Verify Now: http://secure-bank-verification.test/login?id=8841203

Failure to verify will result in loss of access to your funds.

SecureBank Fraud Prevention Team
This is an automated message, please do not reply.
`
  },
  {
    id: "threat_fake_invoice_image_link",
    name: "threat_fake_invoice_image_link.eml",
    category: "threat",
    expectedScoreRange: [75, 95],
    notes: "3-hop chain shows an offshore VPS as true origin, relayed through a bulk-mail provider before reaching the recipient (lookalike vendor domain + geolocation mismatch); DKIM present but fails alignment; DMARC=REJECT policy violated; image attachment + external payment link combo.",
    content: `From: "Apex Office Supplies Billing" <billing@apex-office-supplies.test>
To: accounts.payable@example.com
Subject: Invoice #INV-88214 Overdue - Immediate Action Required
Message-ID: <178938738888.104.6140593106028621871@apex-office-supplies.test>
Date: Mon, 14 Sep 2026 11:58:08 -0000
Return-Path: <no-reply@apex-office-supplies.test>
Received: from mx.example.com (mx.example.com [192.0.2.5]) by
 inbound-gw.example.com with ESMTPS id nv3d for
 <accounts.payable@example.com>; Mon, 14 Sep 2026 12:00:08 -0000
Received: from smtp-out-cluster4.bulkmail-provider.test
 (smtp-out-cluster4.bulkmail-provider.test [198.51.100.23]) by mx.example.com
 with ESMTPS id qv9x; Mon, 14 Sep 2026 11:59:08 -0000
Received: from vps-8841.offshore-hosting.test (vps-8841.offshore-hosting.test
 [203.0.113.140]) by smtp-out-cluster4.bulkmail-provider.test with SMTP id
 ll5e; Mon, 14 Sep 2026 11:58:08 -0000
X-Originating-IP: [203.0.113.140]
Received-SPF: softfail (mx.example.com: transitioning domain of
 apex-office-supplies.test does not strongly designate 198.51.100.23 as
 permitted sender) client-ip=198.51.100.23
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=bulkmail-provider.test; s=selector1; h=From:To:Subject:Date;
 bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=INVALID_ALIGNMENT_DEMO==
Authentication-Results: mx.example.com; spf=softfail
 smtp.mailfrom=apex-office-supplies.test; dkim=fail (signature domain
 bulkmail-provider.test does not align with header.from
 apex-office-supplies.test); dmarc=fail (p=REJECT sp=REJECT dis=NONE)
 header.from=apex-office-supplies.test
X-Spam-Status: Yes, score=6.9 required=5.0
 tests=DKIM_ALIGNMENT_FAIL,URI_PAYMENT_LOOKALIKE,DOMAIN_YOUNG
X-Spam-Score: 6.9
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============2374617180077936185=="

--===============2374617180077936185==
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hello,

Please find attached your overdue invoice screenshot for reference
number and amount due.

To avoid a late fee and service suspension, settle this invoice
immediately via our secure payment portal:

Pay Now: http://apex-office-supplies-payment.test/pay?inv=88214

Regards,
Billing Department
Apex Office Supplies

--===============2374617180077936185==
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice_88214_screenshot.png"
MIME-Version: 1.0

iVBORw0KGgoAAAANSUhEUgAAAaQAAAC0CAYAAADb7VgaAAAO50lEQVR4nO2dPa4stxFG3xYMOHAg
p9qf9uPMC1D8luHAkbUIJQac2YEhe3TRNax/FjnnAw6e73STLFax67vTuoC//fLjj/8GAADYzbfd
AQAAAPyCIQEAwBQwJAAAGAGGBAAAI8CQAABgBBgSAACMwG1IK3nHZ6+rVVZCo/uyXu/en3ef0f1F
5/XWI2vcan/WcdG6deUzuj9vPqzrReOEHDCk5IMW3Zf1evf+vPuM7i86r7ceWeNW+7OOi9atK5/R
/XnzYV0vGifkEDYk6/WqcVlxV83v3XdXXqrzqW0Iu89Z9X2769ddh+48nVIHeAZDSqbqga7OS3U+
uxthNN9V9+2uX3cduvN0Sh3gGQwpmVPzUp3Pr/etft6Vz+r7dtevuw7deTqlDvAMhpTMqXmpzmd3
I/SOq75vd/2669Cdp1PqAM+0/1GDVtbx1rirEqqNP3tcNC9V+7XGrx3vzVdW3Fnnqrt+3jp05/P2
OsAzGFIy2vizx0XzUrVfa/za8d58ZcWdda666+etQ3c+b68DPFP2ys47buqBrd5f1bhqsvJuvZ49
365z1V2/7vPZnadT6gDPYEjJdD/wux+krLxbr2fPt+tcddev+3x25+mUOsAzGFIyVQ+0d95qsvKe
Xb9p62WPq6pX1fntytMpdYBnMKRkqh5o77zVZOU9u37T1sseV1WvqvPbladT6gDPHGNIK1XHbZ0/
Gp92vFa79xm97q2fNx/Z46TxWmXXLXrdG5/3fut61nxqlVUHeAZDSiYrPu14rXbvM3rdWz9vPrLH
SeO1yq5b9Lo3Pu/91vWs+dQqqw7wDP/3EwAAMAIMCQAARoAhAQDACDAkAAAYAYYEAAAjwJAAAGAE
GBIAAIzg259++PHfAAAAu8GQAABgBBgSAACMAEMCAIARYEgAADACDAkAAEaAIQEAwAgwJAAAGIHa
kP7wxz8DAACYwZAAAGAEGBIAAIwAQwIAgBFgSAAAMAIMCQAARoAhAcBY0J2S6o0hAcBY0J2S6o0h
AcBY0J2S6o0hAcBY0J2S6o0hAcBY0J2S6o0hAcBY0J2S6r3dkH799Z+PWO+PjpPGa+fNfhC795ed
V+/+quLMrkP2eak611Xntut8ojslnRMMCUPCkAritJ4XDAlD+iRJ52SbIUUf3Oxx1nirG2DX/rL2
YTWiXXFWrzftXFc9D111R3dKqjeG5IwXQ+ptTBjSrOehq+7oTkn1xpCaGtXuvFTvB0Oqrd/pz0O1
IX379q0VrzLn8q43IS9SvTGkpka1Oy/V+8GQaut3+vOAIclxVmpqXqR6bzekFdZx3vWqG1VXQ5ue
l2ijj8aZte7p9dtlSNY4T2+8mjgrNTUvUr0xJAwJQ3Kse3r9MCQMCUNKfHCrHhzt+KpGeFpevI1p
V5zVdTqlfqfU3dt4s3WLIU2ZX6o3huQcjyH1NiYMaWY+MaTZmpoXqd4YUlGcVQ/4lLx459kdZ3Wd
TqnfKXWvboxT5q/S1LxI9caQiuKsesCn5MU7z+44q+t0Sv1OqXt1Y6yY3/taruJ13qS8vEqq98cZ
0oqsOLMe9FV8uxuTNU5tPbLql72v6P6m1C+az6z7V+OzGmP0P87fakideXmVdE4wJAwJQ0qI77T6
YUgYkrTmRxoSAMCKExsvhrSWVG8MCQDGcmLjxZDWkuqNIQHAWE5vvLs1NS9SvTEkABjL6Y13t6bm
Rao3hgQAYzm98Wri6BynmRdDAgB4QKupjVcTR+c4zbwYEgDAA1pNbbyaODrHaebFkAAAHtBqauPV
xNE5TjPvRxvSX/768yOr+63Xs+bVxlk1brU/67goX+etysuuukfzsvu8eOsYPQdZaDW18Wri6Byn
mRdDOqAxTWkwGFJv3aN52X1evHWMnoMstJraeHdral6kem83JOuB1jbmrMaU1dCy7+tqCNZ1qxph
d92z8lEdZ/YvWt79TjekqG41pF3zS/XGkJoaGoZ0Vt2z8lEdJ4YUa4xT5n9aI2OdqXmR6n2sIWl/
3v3AV92XNS5arxWn1j2al13nrOvcRX8R0VLdGKfM/7QGhoQhlTUKDOmsukfzsuucdZ07DClfGNIF
hvT1c+uDHW0E0wzJawxZdYs2tml19+Y1atDe+kXHReuQfb68jbGaCnUY0pS8SPXGkDCkEBiSbby3
jt5z0F2H7PN1euO1CEO6yJC8128zpOyGsFovaoRT6x7Ni/V6dFx0P1HDrPoF6PTGu1tT8yLVG0PC
kEL1wpBy4sSQnjm98e7W1LxI9f44Qzp9vexxUaKNfmodsvKhvV41ruv8VOX1RFUY2Mmm+CSp3hjS
Yet1NwTruhgShpTJicKQ1pLqvd2QrF/5dzUm76uJ7HGrxmQdl93IqvJyiiF1n5do3bPOCYb0f2FI
a0n1xpCGNRhto8luTF4wpL3nBUOaJwxpLane2w0JAEDiRGFIa0n1xpAAYCzoTkn1xpAAYCzoTkn1
xpAAYCwZmvQK7fZYtJLqjSEBwFgydLsJTIpFK6neGBIAjCVDt5vApFi0kuq9zZD+9vd//I+na9LP
r+Ok8db13l1/t543Fm28nn1o9q/dQ2Rvq/pmX4M7ydDtJjApFq2kem81pKf/vfrZ24y861k/e7rH
28xX61nMOOOadz1t7ivqDmeTodtNYFIsWkn1HmFIX3+uNiTLetbPnu7xxKydOzpXhSG9m+fpG5h1
HHwO6E5J9T7SkDyvbqKvAVevkLIb5qpRW14tfr2u3YPl2rv8PO3r67/W/VU2QZgDulNSvY80JM/B
vuEbUlYz1uYzkmtp7Ndr2m9MWd/W4Cy0mvTailjWkuo9wpBWzSbbkCzrWT97uifTkDIe8g5D0l7z
xoIhfQZaTWq8xLKWVO+Rf2X37rrmVZF1vYghVbxKqty7Zc7oN6To60PtOLgXrSY1XmJZS6r3NkMC
AFih1aTGSyxrSfXGkABgLFpNarzEspZUbwwJAMaC7pRUbwwJAMaC7pRUbwwJAMaSoUmvrYjlv5Lq
jSEBwFgyhAnMi0WqN4YEAGPJECYwLxap3hgSAIwlQ5jAvFikemNIADCWDGEC82KR6r3VkP7100+/
Q/r89drX6+/m+zrn13s1sUR4F6f08+qaJmeWWCL59ORMW9dI/bL24Klf5Fxn5yxrD1n18zxb6E5J
9d5mSJqDKTVP6z2rcdpYPEb1zgCe5l1d06zzzpSq8unNh2V/Ul6s+ck4L1Lc3hiqcqYdV/0cWZ+3
30B3Sqo3hrTJkJ7+1V6zNp+OfHrzYd3fU148+ck4L9EadeVMM67TkCy5qBav0PrmfJVU7zGv7CyN
4t1rA8+DpInFS7YhSXFGGow3n56crfaw2l+nIUnxPNVEu86OnElxZ5yXjFjeUa0bTGBSLFpJ9R7z
Rw3dv9F7G1TFvrSNIvobaGU+rfmIGkqHIVXXqCtn737x8da9on5PVOsGE5gUi1ZSvTEkQyynGJJ0
3yRDitbkEw0pkjPPN5bVZ1mxvKNaN5jApFi0kuq99b8hrV5fZDbQr2taY/E2Euvri9U1KVZNLq2x
rD7z5C2yv9U81rPkPWeWWLT7q8jZ63Vrzrxn13s+Jap1gwlMikUrqd5jviEBAHwF3Smp3hgSAIwF
3Smp3hgSAIzlRE16hTYplldJ9caQAGAsJ2qSCUyK5VVSvTEkABjLiZpkApNieZVUbwwJAMZyoiaZ
wKRYXiXVG0MCgLGcqEkmMCmWV0n1xpAAYCzoTkn1xpAAYCzoTkn1xpAAYCxaPb1GqsSrSa/QKmLR
Sqo3hgQAY9EKQ8KQMCQAKEUrDAlDwpAAoBStMCQMKWRI33/4AeBqdjfzG9CqurFiSLnCkACa2d3M
b0CrUwwJ/VcYEkAzu5v5DWiFIZ0lDAmgmd3N/Aa0mmRIk16hTYrlVRgSQDO7m/kNaLVqntE/WsCQ
MCSAo9ndzG9AKwxpfiyvwpAAmtndzG9AKwxpfiyvwpAAmtndzG9AKwxpfiyvOtaQJK3uj16vXi86
bqXdzdi63+rxVedsJWuj7W7sVeM+2ZDQWhgShrSVaFzV+/LWfaUpjd67XnecGNJn6DhD+k3Rhr36
fIqxeBuw9j7r+tWN3rq/qjir6v5deGX3m1YNOLuhW693x/kphjTpFdrOWDAk4fPqxmSN02o02vu6
G720jnXd6jir6v4dQ8KQFHFiSB9iSNqfqxtTdpyexjih0VvXiY73rpNV9+9GQ/qqakNardcdJ4ZU
M25qLBgShvQ4zjveGpd1neh47zpZdf+OIWFIijgxpMMMaaWsRi993j1utT9PY9yJtm4ZBrAjznfj
NAax+jnbkLTrdceJIdWMmxoLhoQhbUFbt2ied8X5bhyGhCGhZx1rSLsNYtq4rEb9VVWNXopzlZeV
svaXVQdp3KrBrowgu6Fr1+uOs9qQosKQcoUhXTIuu2F6x3vX0+Zlpaz9ZdVBGre70XvX644TQ7rj
dZ5WGNIl47Ibpne8df7oetZxWfmLxmtt5KvrWsOIrpcVJ4bkXwNDwpDGj8tumN7x1vmj61nHZeUv
Gi+GhCF518CQPtiQVo3U24CrG6H2vt1E46zOh7d+78Z5Gq23UXsbe9W43YZUTYUwJAwp3JiiDW1X
A+4mGmd1Prz1ezcOQ8KQLMKQBhsSwOl0Ne2biTTQ0wzpk4QhATSzu5nfgFYY0lnCkACa2d3MbwDd
KQwJoJndzfwG0J3CkACa2d3MbwDdKQwJoJndzfwG0J3CkACa2d3MbwDdKQwJoJndzfwG0J3CkACa
2d3MbwDdKQwJoJndzfwG0J3CkACa2d3MbwDdKQwJoJndzfwG0J0aZ0gAAACvYEgAADACDAkAPoq/
/PXn3+G59vXzdz9r49Cu591bxR6ywZAA4GN412gt115//trgrc1cMg5tbJY4Pdc6wZAA4GOoMqSn
fyMxdRtSJP5MMCQA+Ci0r62kMe++EVlfsUnrZr0G1O7Buk4VGBIAfCzaV22Vr7sqvyFZ58SQAAA2
gSHpx3eAIQHAx2D5K7SuPwiQ7vf+lZ32GoYEAAAgkG5IAAAAlWBIAAAwAgwJAABGgCEBAMAIMCQA
ABgBhgQAACPAkAAAYAQYEgAAjABDAgCAEWBIAAAwgv8A4U1nf2Fz8WgAAAAASUVORK5CYII=

--===============2374617180077936185==--
`
  },
  {
    id: "moderate_bec_gift_card_request",
    name: "moderate_bec_gift_card_request.eml",
    category: "moderate",
    expectedScoreRange: [60, 80],
    notes: "Only 2 hops, both technically SPF/DKIM 'pass' - but the passing domain (webmail-service.test) doesn't match the displayed From domain (example-corp.test), so DMARC alignment fails; that From/DKIM-domain mismatch plus gift-card language is the actual signal, since infra-level checks alone look clean. Score sits below the spam threshold on purpose to show why content + header cross-checks both matter.",
    content: `From: "Priya Sharma" <priya.sharma@example-corp.test>
To: new.hire@example-corp.test
Subject: Quick favor - are you at your desk?
Message-ID: <178938738888.104.3073486985462028272@example-corp.test>
Date: Mon, 14 Sep 2026 12:02:08 -0000
Reply-To: priya.sharma1990@webmail-service.test
Return-Path: <priya.sharma1990@webmail-service.test>
Received: from mx.example-corp.test (mx.example-corp.test [192.0.2.44]) by
 inbound-gw.example-corp.test with ESMTPS id kd8p for
 <new.hire@example-corp.test>; Mon, 14 Sep 2026 12:03:08 -0000
Received: from mail-out.webmail-service.test (mail-out.webmail-service.test
 [192.0.2.201]) by mx.example-corp.test with ESMTPS id we2r; Mon, 14 Sep 2026
 12:02:08 -0000
X-Originating-IP: [192.0.2.201]
Received-SPF: pass (mx.example-corp.test: domain of webmail-service.test
 designates 192.0.2.201 as permitted sender) client-ip=192.0.2.201
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=webmail-service.test;
 s=main; h=From:To:Subject:Date; bh=aGVsbG93b3JsZA==; b=DEMO_SIGNATURE==
Authentication-Results: mx.example-corp.test; spf=pass
 smtp.mailfrom=webmail-service.test; dkim=pass header.d=webmail-service.test;
 dmarc=fail (p=QUARANTINE) header.from=example-corp.test
 reason=domain_mismatch_from_vs_dkim
X-Spam-Status:
 No, score=4.1 required=5.0 tests=REPLYTO_DOMAIN_MISMATCH,GIFT_CARD_LANGUAGE
X-Spam-Score: 4.1
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hi,

Are you at your desk? I'm in back-to-back meetings and need a quick
favor. Can you pick up 5 gift cards ($100 each) for a client
appreciation event? I'll reimburse you as soon as I'm out.

Just scratch the back and send me the codes by email once you have
them, it's time sensitive.

Thanks so much,
Priya
Sent from my iPhone
`
  },
  {
    id: "moderate_marketing_tracking_link",
    name: "moderate_marketing_tracking_link.eml",
    category: "moderate",
    expectedScoreRange: [25, 45],
    notes: "3-hop chain entirely within the sender's own ESP infrastructure (internal cluster -> bulk mailer -> recipient), SPF/DKIM both pass and aligned, but DMARC has no enforced policy and the click-through URL is a redirect-style tracker - infra looks legitimate, risk is purely in link/behavior pattern.",
    content: `From: "DealHub Weekly" <deals@dealhub-newsletter.test>
To: subscriber@example.com
Subject: You left something in your cart - 20% off inside
Message-ID: <178938738889.104.3315784782772319915@dealhub-newsletter.test>
Date: Mon, 14 Sep 2026 11:53:08 -0000
List-Unsubscribe: <http://dealhub-newsletter.test/unsubscribe?u=88231>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Return-Path: <bounce@dealhub-newsletter.test>
Received: from mx.example.com (mx.example.com [192.0.2.5]) by
 inbound-gw.example.com with ESMTPS id pl4m for <subscriber@example.com>; Mon,
 14 Sep 2026 11:54:08 -0000
Received: from bulk-mailer-07.dealhub-newsletter.test
 (bulk-mailer-07.dealhub-newsletter.test [198.51.100.150]) by mx.example.com
 with ESMTP id b7n4; Mon, 14 Sep 2026 11:53:08 -0000
Received: from esp-cluster-internal.dealhub-newsletter.test
 (esp-cluster-internal.dealhub-newsletter.test [10.20.4.31]) by
 bulk-mailer-07.dealhub-newsletter.test with ESMTP id kc9z; Mon, 14 Sep 2026
 11:53:08 -0000
X-Originating-IP: [198.51.100.150]
Received-SPF: pass (mx.example.com: domain of dealhub-newsletter.test
 designates 198.51.100.150 as permitted sender) client-ip=198.51.100.150
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=dealhub-newsletter.test; s=esp1; h=From:To:Subject:Date;
 bh=OGYyZjE3ZDQ5MzA=; b=VALID_ALIGNED_SIGNATURE==
Authentication-Results: mx.example.com; spf=pass
 smtp.mailfrom=dealhub-newsletter.test; dkim=pass
 header.d=dealhub-newsletter.test; dmarc=none (no policy record published)
 header.from=dealhub-newsletter.test
X-Spam-Status: No, score=3.2 required=5.0
 tests=BULK_MAILER,REDIRECT_TRACKING_URL,MARKETING_URGENCY
X-Spam-Score: 3.2
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hi there,

We noticed you left an item in your cart! Complete your purchase in
the next 24 hours and get an extra 20% off with code SAVE20.

Shop Now: http://dealhub-newsletter.test/track/click?id=xk29da&redir=cart

Not interested anymore? Unsubscribe here:
http://dealhub-newsletter.test/unsubscribe?u=88231

DealHub Weekly Team
`
  },
  {
    id: "good_legitimate_internal_email",
    name: "good_legitimate_internal_email.eml",
    category: "good",
    expectedScoreRange: [0, 15],
    notes: "Full 2-hop chain stays entirely inside the corporate network (internal relay -> corp MX), all private RFC1918 IPs; SPF/DKIM/DMARC all pass and aligned; ARC chain present and valid (shows it passed through enterprise mail security intact); threaded reply with In-Reply-To/References/Thread-Topic; spam score near zero - clean baseline for contrast.",
    content: `From: "Arjun Mehta" <arjun.mehta@example-corp.test>
To: monish.k@example-corp.test
Cc: team-leads@example-corp.test
Subject: Re: Notes from today's sprint planning
Message-ID: <178938738889.104.11257990977116894356@example-corp.test>
In-Reply-To: <178938738889.104.5069050395238912277@example-corp.test>
References: <178938738889.104.5069050395238912277@example-corp.test>
Thread-Topic: Notes from today's sprint planning
Date: Mon, 14 Sep 2026 12:03:08 -0000
Return-Path: <arjun.mehta@example-corp.test>
Received: from mx.example-corp.test (mx.example-corp.test [192.0.2.10]) by
 inbound-gw.example-corp.test with ESMTPS id f4d8 for
 <monish.k@example-corp.test>; Mon, 14 Sep 2026 12:03:08 -0000
Received: from mail-relay-internal-02.example-corp.test
 (mail-relay-internal-02.example-corp.test [10.10.2.15]) by
 mx.example-corp.test with ESMTPS (TLS1.3) id gh7k; Mon, 14 Sep 2026 12:03:08
 -0000
X-Originating-IP: [10.10.2.15]
Received-SPF: pass (mx.example-corp.test: domain of example-corp.test
 designates 10.10.2.15 as permitted sender) client-ip=10.10.2.15
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example-corp.test;
 s=corp2024; h=From:To:Subject:Date:Message-ID; bh=ZjQ4YzM4ZjQ3YzM0=;
 b=VALID_ALIGNED_SIGNATURE==
ARC-Authentication-Results: i=1; mx.example-corp.test; spf=pass
 smtp.mailfrom=example-corp.test; dkim=pass header.d=example-corp.test;
 dmarc=pass header.from=example-corp.test
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
 d=example-corp.test; s=arc1; h=From:To:Subject:Date; bh=ZjQ4YzM4ZjQ3YzM0=;
 b=ARC_DEMO_SIGNATURE==
ARC-Seal:
 i=1; a=rsa-sha256; d=example-corp.test; s=arc1; t=12345678; b=ARC_SEAL_DEMO==
Authentication-Results: mx.example-corp.test; spf=pass
 smtp.mailfrom=example-corp.test; dkim=pass header.d=example-corp.test;
 dmarc=pass (p=REJECT) header.from=example-corp.test
X-Spam-Status: No, score=0.1 required=5.0 tests=none
X-Spam-Score: 0.1
X-Mailer: Microsoft Outlook 16.0
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hi Monish,

Quick recap from today's sprint planning:

- Forensic report PDF generation moved to top priority for this sprint
- IP geolocation lookup module: on track, review scheduled Thursday
- Gemini scoring integration: needs one more round of prompt tuning

No blockers on my end. Let me know if you want to sync before Thursday's
review.

Thanks,
Arjun
`
  }
];
