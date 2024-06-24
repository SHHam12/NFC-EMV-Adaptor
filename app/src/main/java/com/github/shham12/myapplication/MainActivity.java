package com.github.shham12.myapplication;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.github.shham12.nfc_emv_adaptor.EMVParser;
import com.github.shham12.nfc_emv_adaptor.parser.IProvider;
import com.github.shham12.nfc_emv_adaptor.parser.impl.Provider;


import java.nio.charset.StandardCharsets;
import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "NFC";
    private NfcAdapter nfcAdapter;
    private TextView textView;

    private static final String CAPK =
            "<CAPK>\n" +
            "    <ExtensionData />\n" +
            "    <ArrayOfCAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>20D213126955DE205ADC2FD2822BD22DE21CF9A8</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>D9FD6ED75D51D0E30664BD157023EAA1FFA871E4DA65672B863D255E81E137A51DE4F72BCC9E44ACE12127F87E263D3AF9DD9CF35CA4A7B01E907000BA85D24954C2FCA3074825DDD4C0C8F186CB020F683E02F2DEAD3969133F06F7845166ACEB57CA0FC2603445469811D293BFEFBAFAB57631B3DD91E796BF850A25012F1AE38F05AA5C4D6D03B1DC2E568612785938BBC9B3CD3A910C1DA55A5A9218ACE0F7A21287752682F15832A678D6E1ED0B</Modulus>\n" +
            "        <PKIndex>08</PKIndex>\n" +
            "        <RID>A000000003</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>1FF80A40173F52D7D27E0F26A146A1C8CCB29046</CheckSum>\n" +
            "        <ExpiryDate>12312027</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>9D912248DE0A4E39C1A7DDE3F6D2588992C1A4095AFBD1824D1BA74847F2BC4926D2EFD904B4B54954CD189A54C5D1179654F8F9B0D2AB5F0357EB642FEDA95D3912C6576945FAB897E7062CAA44A4AA06B8FE6E3DBA18AF6AE3738E30429EE9BE03427C9D64F695FA8CAB4BFE376853EA34AD1D76BFCAD15908C077FFE6DC5521ECEF5D278A96E26F57359FFAEDA19434B937F1AD999DC5C41EB11935B44C18100E857F431A4A5A6BB65114F174C2D7B59FDF237D6BB1DD0916E644D709DED56481477C75D95CDD68254615F7740EC07F330AC5D67BCD75BF23D28A140826C026DBDE971A37CD3EF9B8DF644AC385010501EFC6509D7A41</Modulus>\n" +
            "        <PKIndex>09</PKIndex>\n" +
            "        <RID>A000000003</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>EBFA0D5D06D8CE702DA3EAE890701D45E274C845</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>B8048ABC30C90D976336543E3FD7091C8FE4800DF820ED55E7E94813ED00555B573FECA3D84AF6131A651D66CFF4284FB13B635EDD0EE40176D8BF04B7FD1C7BACF9AC7327DFAA8AA72D10DB3B8E70B2DDD811CB4196525EA386ACC33C0D9D4575916469C4E4F53E8E1C912CC618CB22DDE7C3568E90022E6BBA770202E4522A2DD623D180E215BD1D1507FE3DC90CA310D27B3EFCCD8F83DE3052CAD1E48938C68D095AAC91B5F37E28BB49EC7ED597</Modulus>\n" +
            "        <PKIndex>05</PKIndex>\n" +
            "        <RID>A000000004</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>F910A1504D5FFB793D94F3B500765E1ABCAD72D9</CheckSum>\n" +
            "        <ExpiryDate>12312029</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>CB26FC830B43785B2BCE37C81ED334622F9622F4C89AAE641046B2353433883F307FB7C974162DA72F7A4EC75D9D657336865B8D3023D3D645667625C9A07A6B7A137CF0C64198AE38FC238006FB2603F41F4F3BB9DA1347270F2F5D8C606E420958C5F7D50A71DE30142F70DE468889B5E3A08695B938A50FC980393A9CBCE44AD2D64F630BB33AD3F5F5FD495D31F37818C1D94071342E07F1BEC2194F6035BA5DED3936500EB82DFDA6E8AFB655B1EF3D0D7EBF86B66DD9F29F6B1D324FE8B26CE38AB2013DD13F611E7A594D675C4432350EA244CC34F3873CBA06592987A1D7E852ADC22EF5A2EE28132031E48F74037E3B34AB747F</Modulus>\n" +
            "        <PKIndex>06</PKIndex>\n" +
            "        <RID>A000000004</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>D18AB9F1518FBC0F6EB0EEFB00C5D07CAE8A2197</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>010001</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>DB43A71FF30392069A9600143DCB628A4DABDFE69E31CB6151D9A2EB18A53ABA1EF75518CD3EDA29B96D55B002870A649AAFC65CE472BD01352C2D2E77D4EE352B3A64BC2CC170E29D426D7B3317BD3C4FC32EA2151CA0F1071A2ACFECD70468D3EBC7A44440DD63EC9499F302348BB6235F964BF3CAA30B29939B9901C42B5540BF4F837DD898F5392076F9B95F0EBCB6846374FFE71895A422775D95CABA9C25510627D4F7B57A3DBD755608EDD843</Modulus>\n" +
            "        <PKIndex>06</PKIndex>\n" +
            "        <RID>A000000277</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>46EAD2ED0B8645D4DCB2AE4B1D285A0632B452D4</CheckSum>\n" +
            "        <ExpiryDate>12312025</ExpiryDate>\n" +
            "        <Exponent>010001</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>AB1B0667B2A68883477B2ED48F3068CB0F57ABBEC93E0AF40180BACD895120E36E2710784599CDE9035550D96BD6C5CEA55C4E8C88A5D0A81CE1309559BCE91930C7AA3E3D0A2D79A6036BE03C4000658A78ECA742034BE5FB0E08D530C7FF9458211E78E33E3803F8DFF24A4117EE0EDFE7A98CB3AE2ECCB2A3C3A75C32512EDD1183CF218BE1642FA78430A18A495E6FEFA7B98860C6FCEBFD27537D34F4E55B9CBDEB19DF029BDF00993E1A2E0B9E89E1B49777FCB7C1610CDA94A488C9177908B75C48DFE3F8BBD52886233B44B1A58373D5AFD0F309ABB939C39DF95D923F76B7300E83D182C2922EBB9FD018867A0E6D179EFF8C87</Modulus>\n" +
            "        <PKIndex>08</PKIndex>\n" +
            "        <RID>A000000277</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>A73472B3AB557493A9BC2179CC8014053B12BAB4</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>C8D5AC27A5E1FB89978C7C6479AF993AB3800EB243996FBB2AE26B67B23AC482C4B746005A51AFA7D2D83E894F591A2357B30F85B85627FF15DA12290F70F05766552BA11AD34B7109FA49DE29DCB0109670875A17EA95549E92347B948AA1F045756DE56B707E3863E59A6CBE99C1272EF65FB66CBB4CFF070F36029DD76218B21242645B51CA752AF37E70BE1A84FF31079DC0048E928883EC4FADD497A719385C2BBBEBC5A66AA5E5655D18034EC5</Modulus>\n" +
            "        <PKIndex>0F</PKIndex>\n" +
            "        <RID>A000000025</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>10</Algorithm>\n" +
            "        <CheckSum>C729CF2FD262394ABC4CC173506502446AA9B9FD</CheckSum>\n" +
            "        <ExpiryDate>12312029</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>CF98DFEDB3D3727965EE7797723355E0751C81D2D3DF4D18EBAB9FB9D49F38C8C4A826B99DC9DEA3F01043D4BF22AC3550E2962A59639B1332156422F788B9C16D40135EFD1BA94147750575E636B6EBC618734C91C1D1BF3EDC2A46A43901668E0FFC136774080E888044F6A1E65DC9AAA8928DACBEB0DB55EA3514686C6A732CEF55EE27CF877F110652694A0E3484C855D882AE191674E25C296205BBB599455176FDD7BBC549F27BA5FE35336F7E29E68D783973199436633C67EE5A680F05160ED12D1665EC83D1997F10FD05BBDBF9433E8F797AEE3E9F02A34228ACE927ABE62B8B9281AD08D3DF5C7379685045D7BA5FCDE58637</Modulus>\n" +
            "        <PKIndex>10</PKIndex>\n" +
            "        <RID>A000000025</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>17F971CAF6B708E5B9165331FBA91593D0C0BF66</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>8EEEC0D6D3857FD558285E49B623B109E6774E06E9476FE1B2FB273685B5A235E955810ADDB5CDCC2CB6E1A97A07089D7FDE0A548BDC622145CA2DE3C73D6B14F284B3DC1FA056FC0FB2818BCD7C852F0C97963169F01483CE1A63F0BF899D412AB67C5BBDC8B4F6FB9ABB57E95125363DBD8F5EBAA9B74ADB93202050341833DEE8E38D28BD175C83A6EA720C262682BEABEA8E955FE67BD9C2EFF7CB9A9F45DD5BDA4A1EEFB148BC44FFF68D9329FD</Modulus>\n" +
            "        <PKIndex>04</PKIndex>\n" +
            "        <RID>A000000152</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>12BCD407B6E627A750FDF629EE8C2C9CC7BA636A</CheckSum>\n" +
            "        <ExpiryDate>12312026</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>E1200E9F4428EB71A526D6BB44C957F18F27B20BACE978061CCEF23532DBEBFAF654A149701C14E6A2A7C2ECAC4C92135BE3E9258331DDB0967C3D1D375B996F25B77811CCCC06A153B4CE6990A51A0258EA8437EDBEB701CB1F335993E3F48458BC1194BAD29BF683D5F3ECB984E31B7B9D2F6D947B39DEDE0279EE45B47F2F3D4EEEF93F9261F8F5A571AFBFB569C150370A78F6683D687CB677777B2E7ABEFCFC8F5F93501736997E8310EE0FD87AFAC5DA772BA277F88B44459FCA563555017CD0D66771437F8B6608AA1A665F88D846403E4C41AFEEDB9729C2B2511CFE228B50C1B152B2A60BBF61D8913E086210023A3AA499E423</Modulus>\n" +
            "        <PKIndex>05</PKIndex>\n" +
            "        <RID>A000000152</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>874B379B7F607DC1CAF87A19E400B6A9E25163E8</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>ADF05CD4C5B490B087C3467B0F3043750438848461288BFEFD6198DD576DC3AD7A7CFA07DBA128C247A8EAB30DC3A30B02FCD7F1C8167965463626FEFF8AB1AA61A4B9AEF09EE12B009842A1ABA01ADB4A2B170668781EC92B60F605FD12B2B2A6F1FE734BE510F60DC5D189E401451B62B4E06851EC20EBFF4522AACC2E9CDC89BC5D8CDE5D633CFD77220FF6BBD4A9B441473CC3C6FEFC8D13E57C3DE97E1269FA19F655215B23563ED1D1860D8681</Modulus>\n" +
            "        <PKIndex>12</PKIndex>\n" +
            "        <RID>A000000065</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>C0D15F6CD957E491DB56DCDD1CA87A03EBE06B7B</CheckSum>\n" +
            "        <ExpiryDate>12312026</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>AEED55B9EE00E1ECEB045F61D2DA9A66AB637B43FB5CDBDB22A2FBB25BE061E937E38244EE5132F530144A3F268907D8FD648863F5A96FED7E42089E93457ADC0E1BC89C58A0DB72675FBC47FEE9FF33C16ADE6D341936B06B6A6F5EF6F66A4EDD981DF75DA8399C3053F430ECA342437C23AF423A211AC9F58EAF09B0F837DE9D86C7109DB1646561AA5AF0289AF5514AC64BC2D9D36A179BB8A7971E2BFA03A9E4B847FD3D63524D43A0E8003547B94A8A75E519DF3177D0A60BC0B4BAB1EA59A2CBB4D2D62354E926E9C7D3BE4181E81BA60F8285A896D17DA8C3242481B6C405769A39D547C74ED9FF95A70A796046B5EFF36682DC29</Modulus>\n" +
            "        <PKIndex>14</PKIndex>\n" +
            "        <RID>A000000065</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>03BB335A8549A03B87AB089D006F60852E4B8060</CheckSum>\n" +
            "        <ExpiryDate>06012022</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>A3767ABD1B6AA69D7F3FBF28C092DE9ED1E658BA5F0909AF7A1CCD907373B7210FDEB16287BA8E78E1529F443976FD27F991EC67D95E5F4E96B127CAB2396A94D6E45CDA44CA4C4867570D6B07542F8D4BF9FF97975DB9891515E66F525D2B3CBEB6D662BFB6C3F338E93B02142BFC44173A3764C56AADD202075B26DC2F9F7D7AE74BD7D00FD05EE430032663D27A57</Modulus>\n" +
            "        <PKIndex>02</PKIndex>\n" +
            "        <RID>A000000333</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>87F0CD7C0E86F38F89A66F8C47071A8B88586F26</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>B0627DEE87864F9C18C13B9A1F025448BF13C58380C91F4CEBA9F9BCB214FF8414E9B59D6ABA10F941C7331768F47B2127907D857FA39AAF8CE02045DD01619D689EE731C551159BE7EB2D51A372FF56B556E5CB2FDE36E23073A44CA215D6C26CA68847B388E39520E0026E62294B557D6470440CA0AEFC9438C923AEC9B2098D6D3A1AF5E8B1DE36F4B53040109D89B77CAFAF70C26C601ABDF59EEC0FDC8A99089140CD2E817E335175B03B7AA33D</Modulus>\n" +
            "        <PKIndex>03</PKIndex>\n" +
            "        <RID>A000000333</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>F527081CF371DD7E1FD4FA414A665036E0F5E6E5</CheckSum>\n" +
            "        <ExpiryDate>12312031</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>BC853E6B5365E89E7EE9317C94B02D0ABB0DBD91C05A224A2554AA29ED9FCB9D86EB9CCBB322A57811F86188AAC7351C72BD9EF196C5A01ACEF7A4EB0D2AD63D9E6AC2E7836547CB1595C68BCBAFD0F6728760F3A7CA7B97301B7E0220184EFC4F653008D93CE098C0D93B45201096D1ADFF4CF1F9FC02AF759DA27CD6DFD6D789B099F16F378B6100334E63F3D35F3251A5EC78693731F5233519CDB380F5AB8C0F02728E91D469ABD0EAE0D93B1CC66CE127B29C7D77441A49D09FCA5D6D9762FC74C31BB506C8BAE3C79AD6C2578775B95956B5370D1D0519E37906B384736233251E8F09AD79DFBE2C6ABFADAC8E4D8624318C27DAF1</Modulus>\n" +
            "        <PKIndex>04</PKIndex>\n" +
            "        <RID>A000000333</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>30AB6C5690B74D7117355AFBA07749B5142B57F2</CheckSum>\n" +
            "        <ExpiryDate>12312030</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>95E3D868E014B01210491A6EA00C097D4261AED776930E6D4FCA31C7477E29AEC5B77F7D2F0B6E61B34C876806A71A8FF1EC3E897943BE5524E7A0F7BD23840FF3B1D25C078BC32FE38E57307B413A255E268B795B45CB5B430BEAD8ABFB835F3248AFA34F85DD028DBC77D1EABFA79A2D891806A0B0BC5D25D213188E3E18DB25F45B7942320D1F55D637299334744D5633D954C70E1BAA73C2562F3C142DF9545CE4841653B80D6DD1D88C2F652ABED57551BDCA98C16D77A4139D2F84E5E3633A00DEFB3E865825DB326E6B68DC04B6AE1FAEABB6C867C30E172C94E33FC220C7C7C4342A4356DABE0A5CAB61606B649B5F33B75E35CD</Modulus>\n" +
            "        <PKIndex>05</PKIndex>\n" +
            "        <RID>A000000780</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>D8E9DA9B8461A43F469BBD08CD3A52B0B3AA775F</CheckSum>\n" +
            "        <ExpiryDate>12312027</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>9318623777A684FA329C2DC24AA398678DE27CB2C547C6DB6542125409528823D75F42455789C2F7705D8B77EEA7674F923E3D657C0AB8ADF4941ED3AB2877058D30BE31572BF3D570652ED9F3C9E320BA8D96FF000047FEA4582E6BA368D8FF16BE90843657CB7467D4980C9B2ED67333BFBDAE60CAB42D420A34D648816406112186EA397E7155F5EE3858D8CCACA9D11E9D85BC5373FF4B074D3BAC5C3220003B7096614EB1D7FB9216D22D6B7B7695ADDC109A51D0CACFF438A0763F001711B687BAFCD26671FCA21EDD042B1201FCB01D5807C4E94D23CB3D56E3AD16F1F03DB61381FC7F152A391D8A62BCB9D339E12A23A76F9213</Modulus>\n" +
            "        <PKIndex>F2</PKIndex>\n" +
            "        <RID>A000000768</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>E7ABF106A6704AE58CBA4ACA509FD9EC33A147D5</CheckSum>\n" +
            "        <ExpiryDate>12312027</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>86EFCDB87055ED668CF037EC4177B05B102C01EBAF0318CA2362698012ECED53CF176A06DE4F8A113CA091E7E9BDA6A715E3D89926895DFC320574D02EFFBFF1B81F158B9896651EFF8CBC548C51E7BD68338F5A11171C4540E194A91D9D36A6C4132D3799DF911F32132A0B5CCC632200EFBE5752DCCF930F2B7AB76B81588894604215B193CBF160C5BAA32C89F450D15CF0E6B866D3AA249960B69B18B9B2575D741BB2089102A96E6A42067EF6BB</Modulus>\n" +
            "        <PKIndex>FF</PKIndex>\n" +
            "        <RID>A000000768</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>8E8DFF443D78CD91DE88821D70C98F0638E51E49</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>B362DB5733C15B8797B8ECEE55CB1A371F760E0BEDD3715BB270424FD4EA26062C38C3F4AAA3732A83D36EA8E9602F6683EECC6BAFF63DD2D49014BDE4D6D603CD744206B05B4BAD0C64C63AB3976B5C8CAAF8539549F5921C0B700D5B0F83C4E7E946068BAAAB5463544DB18C63801118F2182EFCC8A1E85E53C2A7AE839A5C6A3CABE73762B70D170AB64AFC6CA482944902611FB0061E09A67ACB77E493D998A0CCF93D81A4F6C0DC6B7DF22E62DB</Modulus>\n" +
            "        <PKIndex>C9</PKIndex>\n" +
            "        <RID>A000000025</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>6BDA32B1AA171444C7E8F88075A74FBFE845765F</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>C23ECBD7119F479C2EE546C123A585D697A7D10B55C2D28BEF0D299C01DC65420A03FE5227ECDECB8025FBC86EEBC1935298C1753AB849936749719591758C315FA150400789BB14FADD6EAE2AD617DA38163199D1BAD5D3F8F6A7A20AEF420ADFE2404D30B219359C6A4952565CCCA6F11EC5BE564B49B0EA5BF5B3DC8C5C6401208D0029C3957A8C5922CBDE39D3A564C6DEBB6BD2AEF91FC27BB3D3892BEB9646DCE2E1EF8581EFFA712158AAEC541C0BBB4B3E279D7DA54E45A0ACC3570E712C9F7CDF985CFAFD382AE13A3B214A9E8E1E71AB1EA707895112ABC3A97D0FCB0AE2EE5C85492B6CFD54885CDD6337E895CC70FB3255E3</Modulus>\n" +
            "        <PKIndex>CA</PKIndex>\n" +
            "        <RID>A000000025</RID>\n" +
            "      </CAPK>\n" +
            "      <CAPK>\n" +
            "        <ExtensionData />\n" +
            "        <Algorithm>01</Algorithm>\n" +
            "        <CheckSum>429C954A3859CEF91295F663C963E582ED6EB253</CheckSum>\n" +
            "        <ExpiryDate>12312024</ExpiryDate>\n" +
            "        <Exponent>03</Exponent>\n" +
            "        <HashAlgorithm>01</HashAlgorithm>\n" +
            "        <Issuer />\n" +
            "        <KeyType />\n" +
            "        <Modulus>996AF56F569187D09293C14810450ED8EE3357397B18A2458EFAA92DA3B6DF6514EC060195318FD43BE9B8F0CC669E3F844057CBDDF8BDA191BB64473BC8DC9A730DB8F6B4EDE3924186FFD9B8C7735789C23A36BA0B8AF65372EB57EA5D89E7D14E9C7B6B557460F10885DA16AC923F15AF3758F0F03EBD3C5C2C949CBA306DB44E6A2C076C5F67E281D7EF56785DC4D75945E491F01918800A9E2DC66F60080566CE0DAF8D17EAD46AD8E30A247C9F</Modulus>\n" +
            "        <PKIndex>92</PKIndex>\n" +
            "        <RID>A000000003</RID>\n" +
            "      </CAPK>\n" +
            "    </ArrayOfCAPK>\n" +
            "    <EMVKeyUpdID>0</EMVKeyUpdID>\n" +
            "  </CAPK>";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textView = findViewById(R.id.textView);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter == null) {
            Toast.makeText(this, "NFC is not available on this device.", Toast.LENGTH_SHORT).show();
            finish();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Intent intent = new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE);
        IntentFilter[] filters = new IntentFilter[]{};
        String[][] techList = new String[][]{new String[]{IsoDep.class.getName()}};
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, filters, techList);
        Log.d(TAG, "Foreground dispatch enabled");
    }

    @Override
    protected void onPause() {
        super.onPause();
        nfcAdapter.disableForegroundDispatch(this);
        Log.d(TAG, "Foreground dispatch disabled");
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Log.d(TAG, "NFC Intent received");
        Log.d(TAG, "NFC Intent getAction:" + intent.getAction());
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            if (tag != null) {
                Log.d(TAG, "NFC tag discovered");
                String[] techList = tag.getTechList();
                boolean isoDepSupported = false;
                for (String tech : techList) {
                    if (tech.equals(IsoDep.class.getName())) {
                        isoDepSupported = true;
                        break;
                    }
                }

                if (isoDepSupported) {
                    readFromNfc(tag);
                } else {
                    Toast.makeText(this, "This NFC tag does not support IsoDep.", Toast.LENGTH_SHORT).show();
                    Log.d(TAG, "IsoDep not supported by this tag");
                }
            } else {
                Log.d(TAG, "No NFC tag found in intent");
            }
        }
    }

    private void readFromNfc(Tag tag) {
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep != null) {
            new Thread(() -> {
                try {
                    isoDep.connect();
                    Log.d(TAG, "IsoDep connection established");
                    IProvider temp = new Provider(isoDep);
                    EMVParser parser = new EMVParser(temp, true, CAPK);
                    Map<String, byte[]> data = parser.readEmvCard();

                    isoDep.close();
                    Log.d(TAG, "IsoDep connection closed");

                    String value50 = new String(data.get("50"));
                    String value5A = data.containsKey("5A") ? bytesToHex(data.get("5A")) : "N/A";
                    runOnUiThread(() -> {
                        textView.setText("Application Label: " + value50 + "\nCard Number: " + value5A);
                    });
                } catch (Exception e) {
                    Log.e(TAG, "Error reading NFC tag", e);
                }
            }).start();
        } else {
            Log.d(TAG, "IsoDep not supported by this tag");
        }
    }

    private void logCommand(byte[] command) {
        runOnUiThread(() -> {
            String hexString = bytesToHex(command);
            textView.append("\nCommand: " + hexString);
            Log.d(TAG, "Command: " + hexString);
        });
    }
    private void logResponse(byte[] response) {
        runOnUiThread(() -> {
            String hexString = bytesToHex(response);
            textView.append("\nResponse: " + hexString);
            Log.d(TAG, "Response: " + hexString);
        });
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
