package com.github.shham12.nfc_emv_adaptor.iso7816emv

import org.junit.Assert
import org.junit.Before
import org.junit.Test


class CaPublicKeyTableTest {
    private var publicKeyTable: CaPublicKeyTable? = null

    @Before
    fun setUp() {
        val xmlString =
            """ 
            <CAPK>
                <ExtensionData />
                <ArrayOfCAPK>
                  <CAPK>
                    <ExtensionData />
                    <Algorithm>01</Algorithm>
                    <CheckSum>20D213126955DE205ADC2FD2822BD22DE21CF9A8</CheckSum>
                    <ExpiryDate>12312024</ExpiryDate>
                    <Exponent>03</Exponent>
                    <HashAlgorithm>01</HashAlgorithm>
                    <Issuer />
                    <KeyType />
                    <Modulus>D9FD6ED75D51D0E30664BD157023EAA1FFA871E4DA65672B863D255E81E137A51DE4F72BCC9E44ACE12127F87E263D3AF9DD9CF35CA4A7B01E907000BA85D24954C2FCA3074825DDD4C0C8F186CB020F683E02F2DEAD3969133F06F7845166ACEB57CA0FC2603445469811D293BFEFBAFAB57631B3DD91E796BF850A25012F1AE38F05AA5C4D6D03B1DC2E568612785938BBC9B3CD3A910C1DA55A5A9218ACE0F7A21287752682F15832A678D6E1ED0B</Modulus>
                    <PKIndex>08</PKIndex>
                    <RID>A000000003</RID>
                  </CAPK>
                  <CAPK>
                    <ExtensionData />
                    <Algorithm>01</Algorithm>
                    <CheckSum>E7ABF106A6704AE58CBA4ACA509FD9EC33A147D5</CheckSum>
                    <ExpiryDate>12312027</ExpiryDate>
                    <Exponent>03</Exponent>
                    <HashAlgorithm>01</HashAlgorithm>
                    <Issuer />
                    <KeyType />
                    <Modulus>86EFCDB87055ED668CF037EC4177B05B102C01EBAF0318CA2362698012ECED53CF176A06DE4F8A113CA091E7E9BDA6A715E3D89926895DFC320574D02EFFBFF1B81F158B9896651EFF8CBC548C51E7BD68338F5A11171C4540E194A91D9D36A6C4132D3799DF911F32132A0B5CCC632200EFBE5752DCCF930F2B7AB76B81588894604215B193CBF160C5BAA32C89F450D15CF0E6B866D3AA249960B69B18B9B2575D741BB2089102A96E6A42067EF6BB</Modulus>
                    <PKIndex>FF</PKIndex>
                    <RID>A000000768</RID>
                  </CAPK>
                </ArrayOfCAPK>
                <EMVKeyUpdID>0</EMVKeyUpdID>
              </CAPK>"""

        publicKeyTable = CaPublicKeyTable(xmlString)
    }

    @Test
    fun testGetPublicKeys() {
        val publicKeys = publicKeyTable!!.getPublicKeys()
        Assert.assertNotNull(publicKeys)
        Assert.assertFalse(publicKeys.isEmpty())
        Assert.assertEquals(1, publicKeys.size.toLong())
    }

    @Test
    fun testFindPublicKey() {
        val publicKey = publicKeyTable!!.findPublicKey("A000000003", "08")
        Assert.assertNotNull(publicKey)
        Assert.assertEquals("A000000003", publicKey!!.rid)
        Assert.assertEquals("08", publicKey.index)
    }

    @Test
    fun testFindNonExistingPublicKey() {
        val publicKey = publicKeyTable!!.findPublicKey("A000000004", "01")
        Assert.assertNull(publicKey)
    }
}
