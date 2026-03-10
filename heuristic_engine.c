/*
 * BytesProtector — C Heuristic Engine v3
 * v3: SUSPICIOUS tier (single injection APIs flagged), EICAR guaranteed,
 *     60+ family patterns, cross-platform bp_memmem, 8MB read.
 *
 * gcc -O2 -shared -fPIC -lm -o libheuristic.so heuristic_engine.c
 * gcc -O2 -shared -o libheuristic.dll heuristic_engine.c -lm   (MinGW)
 * gcc -O2 -DBP_STANDALONE -lm -o bpscan heuristic_engine.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#define BP_CLEAN        0
#define BP_EICAR        1
#define BP_CRITICAL     2
#define BP_HIGH         3
#define BP_MEDIUM       4
#define BP_SUSPICIOUS   5
#define BP_PACKED       6

#define MAX_READ        (8*1024*1024)
#define ENTROPY_PACKED  7.4
#define NAME_MAX_       256

static const void *bp_memmem(const void *h,size_t hl,const void *n,size_t nl){
    if(!nl)return h; if(hl<nl)return NULL;
    const unsigned char *hp=(const unsigned char*)h;
    const unsigned char *np=(const unsigned char*)n;
    const unsigned char *e=hp+hl-nl;
    for(;hp<=e;hp++) if(*hp==*np&&!memcmp(hp,np,nl))return hp;
    return NULL;
}
#define HAS(b,n,lit) (bp_memmem((b),(n),(lit),sizeof(lit)-1)!=NULL)

static double ent(const unsigned char *b,size_t n){
    if(!n)return 0;
    uint64_t f[256]={0};
    for(size_t i=0;i<n;i++)f[b[i]]++;
    double h=0;
    for(int i=0;i<256;i++)if(f[i]){double p=(double)f[i]/n;h-=p*log2(p);}
    return h;
}

static char g_name[NAME_MAX_];

#define DET(code,fmt,...) do{snprintf(g_name,NAME_MAX_,fmt,##__VA_ARGS__);ret=(code);goto done;}while(0)
#define CRIT(s,nm) if(HAS(b,n,s))DET(BP_CRITICAL,"%s",nm)
#define HIGH(s,nm) if(HAS(b,n,s))DET(BP_HIGH,"%s",nm)
#define SUSP(s,nm) if(HAS(b,n,s))DET(BP_SUSPICIOUS,"%s",nm)

int bp_scan_file(const char *path){
    if(!path)return BP_CLEAN;
    FILE *fp=fopen(path,"rb"); if(!fp)return BP_CLEAN;
    fseek(fp,0,SEEK_END);long fsz=ftell(fp);rewind(fp);
    if(fsz<=0){fclose(fp);return BP_CLEAN;}
    size_t rsz=(size_t)fsz<MAX_READ?(size_t)fsz:MAX_READ;
    unsigned char *b=(unsigned char*)malloc(rsz);
    if(!b){fclose(fp);return BP_CLEAN;}
    size_t n=fread(b,1,rsz,fp); fclose(fp);
    int ret=BP_CLEAN; g_name[0]=0;

    /* 1. EICAR */
    CRIT("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR","EICAR.TestFile");

    /* 2. SalineWin */
    CRIT("/v DisableTaskMgr /t reg_dword /d 1 /f","Trojan.SalineWin");
    if(HAS(b,n,"DisableTaskMgr")&&HAS(b,n,"policies\\system"))DET(BP_CRITICAL,"Trojan.SalineWin");
    if(HAS(b,n,"\\\\.\\PhysicalDrive0")&&b[0]=='M'&&b[1]=='Z')DET(BP_CRITICAL,"Trojan.SalineWin.MBRWipe");
    CRIT("SalineWin","Trojan.SalineWin");
    CRIT("salinewin","Trojan.SalineWin");

    /* 3. PHP Webshells */
    CRIT("eval(base64_decode(","PHP.Webshell.Eval");
    CRIT("system($_GET[","PHP.Webshell.System");
    CRIT("exec($_POST[","PHP.Webshell.Exec");
    CRIT("passthru($_REQUEST","PHP.Webshell.Passthru");
    CRIT("shell_exec($_GET","PHP.Webshell.Shell");
    CRIT("assert($_POST[","PHP.Webshell.Assert");

    /* 4. Ransomware */
    CRIT("WNcry@2ol7","Ransomware.WannaCry");
    CRIT("WANACRY!","Ransomware.WannaCry");
    CRIT("WannaCrypt","Ransomware.WannaCry");
    CRIT("CONTI_LOCKER","Ransomware.Conti");
    CRIT("ContiDecryptor","Ransomware.Conti");
    CRIT("sodinokibi","Ransomware.REvil");
    CRIT("!!!-Restore-My-Files-!!!","Ransomware.LockBit");
    CRIT("LockBit_easy_decrypt","Ransomware.LockBit");
    CRIT("RyukReadMe","Ransomware.Ryuk");
    CRIT("RansomHub","Ransomware.RansomHub");
    CRIT("PlayCrypt","Ransomware.Play");
    CRIT("datarestore@firemail.cc","Ransomware.Stop.DJVU");
    CRIT("AkiraRansom","Ransomware.Akira");
    CRIT("BlackSuit","Ransomware.BlackSuit");
    CRIT("ALPHV","Ransomware.BlackCat.ALPHV");
    if(HAS(b,n,"YOUR FILES ARE ENCRYPTED")&&HAS(b,n,"Bitcoin"))DET(BP_CRITICAL,"Ransomware.Generic");
    CRIT("vssadmin delete shadows /all /quiet","Ransomware.ShadowWiper");
    CRIT("wmic shadowcopy delete","Ransomware.ShadowWiper");
    CRIT("bcdedit /set {default} recoveryenabled No","Ransomware.BootRecoveryDisable");

    /* 5. RATs */
    CRIT("AsyncMutex_6SI8OkPnk","Trojan.AsyncRAT");
    CRIT("AsyncClient","Trojan.AsyncRAT");
    CRIT("xwormmutex","Trojan.XWorm");
    CRIT("XWormV","Trojan.XWorm");
    CRIT("DCRat","Trojan.DCRat");
    CRIT("DCRAT_BUILD","Trojan.DCRat");
    CRIT("njRAT","Trojan.njRAT");
    CRIT("Bladabindi","Trojan.njRAT");
    CRIT("QuasarRAT","Trojan.QuasarRAT");
    CRIT("Quasar.Client","Trojan.QuasarRAT");
    CRIT("REMCOS_MUTEX","Trojan.Remcos");
    CRIT("Remcos_SETTINGS","Trojan.Remcos");
    CRIT("ValleyRAT","Trojan.ValleyRAT");
    CRIT("AveMaria","Trojan.WarZone");
    CRIT("WarzoneRAT","Trojan.WarZone");
    CRIT("GH0ST","RAT.Gh0stRAT");
    CRIT("DarkComet-RAT","RAT.DarkComet");
    CRIT("NanoCore Client","RAT.NanoCore");
    CRIT("nanocore_mutex","RAT.NanoCore");
    CRIT("PlugX","Backdoor.PlugX");
    CRIT("PoisonIvy","Backdoor.PoisonIvy");
    CRIT("NetwireRC","RAT.NetwireRC");
    CRIT("OrcusRAT","RAT.OrcusRAT");

    /* 6. Backdoors / C2 */
    CRIT("beacon_metadata","Backdoor.CobaltStrike");
    CRIT("CSLDR_","Backdoor.CobaltStrike");
    CRIT("ReflectiveLoader","Backdoor.CobaltStrike");
    CRIT("metsrv.dll","Backdoor.Meterpreter");
    CRIT("MSF_PAYLOAD","Backdoor.Meterpreter");
    CRIT("meterpreter","Backdoor.Meterpreter");

    /* 7. Infostealers */
    CRIT("RedLineClient","Spyware.RedLine");
    CRIT("red_line_config","Spyware.RedLine");
    CRIT("lumma_stealer","Spyware.LummaC2");
    CRIT("LummaC2","Spyware.LummaC2");
    CRIT("lumma_config","Spyware.LummaC2");
    CRIT("raccoon_stealer","Spyware.Raccoon");
    CRIT("vidar_config","Spyware.Vidar");
    CRIT("vidar_stealer","Spyware.Vidar");
    CRIT("AGENTTESLA","Spyware.AgentTesla");
    CRIT("chromiumPasswords","Spyware.AgentTesla");
    CRIT("FORMBOOK","Spyware.Formbook");
    CRIT("stealc_config","Spyware.StealC");
    CRIT("Rhadamanthys","Spyware.Rhadamanthys");
    CRIT("AuroraStealer","Spyware.Aurora");
    CRIT("HawkEye_Reborn","Spyware.Hawkeye");
    CRIT("loki_pwgrab","Spyware.LokiBot");
    CRIT("AZORult","Spyware.Azorult");
    CRIT("arkei_stealer","Spyware.Arkei");
    CRIT("marsstealer","Miner.MarsTealer");
    CRIT("RisePro","Spyware.RisePro");
    CRIT("MetaStealer","Spyware.MetaStealer");

    /* 8. Miners */
    CRIT("donate.v2.xmrig.com","Miner.XMRig");
    CRIT("pool.minexmr.com","Miner.XMRig");
    CRIT("supportxmr.com","Miner.XMRig");
    HIGH("stratum+tcp://","Miner.Generic.PoolConn");
    HIGH("stratum+ssl://","Miner.Generic.PoolConn");
    HIGH("pool.hashvault.pro","Miner.Generic");

    /* 9. Loaders / Droppers */
    CRIT("GuLoader","Loader.GuLoader");
    CRIT("smokeloader","Loader.SmokeLoader");
    CRIT("BumbleBee","Loader.BumbleBee");
    CRIT("HijackLoader","Loader.HijackLoader");
    CRIT("PureCrypter","Loader.PureCrypter");
    CRIT("DBatLoader","Loader.DBatLoader");
    CRIT("PrivateLoader","Loader.PrivateLoader");
    CRIT("SocGholish","Dropper.SocGholish");
    CRIT("FakeUpdates","Dropper.SocGholish");
    CRIT("GootLoader","Dropper.GootLoader");
    CRIT("amadey_mutex","Dropper.Amadey");
    CRIT("DarkGate","Dropper.DarkGate");
    CRIT("SystemBC","Dropper.SystemBC");
    CRIT("Emmenhtal","Dropper.Emmenhtal");

    /* 10. Worms / Botnets */
    CRIT("EmotetMutex","Worm.Emotet");
    CRIT("Emotet4","Worm.Emotet");
    CRIT("Emotet5","Worm.Emotet");
    CRIT("qbot_mutex","Worm.QakBot");
    CRIT("icedid_mutex","Worm.IcedID");
    CRIT("ATTACK_TCP_SYN","Worm.Mirai");
    CRIT("ZLoader","Worm.ZLoader");
    CRIT("Danabot","Worm.Danabot");
    CRIT("TrickBot","Worm.TrickBot");
    CRIT("Phorpiex","Worm.Phorpiex");

    /* 11. APT / Offensive */
    CRIT("mimikatz","APT.Mimikatz");
    CRIT("sekurlsa::","APT.Mimikatz");
    CRIT("privilege::debug","APT.Mimikatz");
    CRIT("lsadump::dcsync","APT.Mimikatz");
    CRIT("EternalBlue","Exploit.EternalBlue");
    CRIT("DoublePulsar","Exploit.DoublePulsar");

    /* 12. PS droppers */
    CRIT("powershell -w hidden -enc","PS.HiddenDropper");
    CRIT("-NonInteractive -W Hidden -enc","PS.HiddenDropper");
    HIGH("IEX(New-Object Net.WebClient","PS.Downloader");
    HIGH("DownloadString('http","PS.Downloader");
    HIGH("bypass -nop -w hidden","PS.SuspiciousExec");

    /* 13. LOLBins */
    HIGH("certutil -urlcache -f http","LOLBIN.CertutilDL");
    HIGH("certutil.exe -decode","LOLBIN.CertutilDecode");
    HIGH("mshta http","LOLBIN.MshtaRemote");
    HIGH("mshta vbscript:","LOLBIN.MshtaVBS");
    HIGH("regsvr32 /u /s /i:http","LOLBIN.Regsvr32Remote");
    HIGH("wmic process call create","LOLBIN.WmicExec");

    /* 14. Injection COMBO */
    if(HAS(b,n,"CreateRemoteThread")&&HAS(b,n,"WriteProcessMemory")&&HAS(b,n,"VirtualAllocEx"))
        DET(BP_HIGH,"Heuristic.ProcessInjector.FullCombo");
    if(HAS(b,n,"NtUnmapViewOfSection")&&HAS(b,n,"VirtualAllocEx")&&HAS(b,n,"WriteProcessMemory"))
        DET(BP_HIGH,"Heuristic.ProcessHollowing");

    /* 15. SUSPICIOUS single strings — always flagged, low confidence */
    SUSP("CreateRemoteThread","Suspicious.API.CreateRemoteThread");
    SUSP("VirtualAllocEx","Suspicious.API.VirtualAllocEx");
    SUSP("WriteProcessMemory","Suspicious.API.WriteProcessMemory");
    SUSP("NtUnmapViewOfSection","Suspicious.API.ProcessHollowing");
    SUSP("ZwUnmapViewOfSection","Suspicious.API.ProcessHollowing");
    SUSP("SetThreadContext","Suspicious.API.SetThreadContext");
    SUSP("IsDebuggerPresent","Suspicious.API.AntiDebug");
    SUSP("GetAsyncKeyState","Suspicious.API.Keylogger");
    SUSP("SetWindowsHookEx","Suspicious.API.KeyboardHook");
    SUSP("GetForegroundWindow","Suspicious.API.ScreenSpy");
    SUSP("NtSetInformationThread","Suspicious.API.AntiDebug");

    /* 16. PE heuristics */
    if(n>=2&&b[0]=='M'&&b[1]=='Z'){
        if(n>512){
            const unsigned char *inn=(const unsigned char*)bp_memmem(b+64,n-64,"MZ",2);
            if(inn){
                size_t off=inn-b;
                if(off+0x40<n){
                    uint32_t lfa=0; memcpy(&lfa,inn+0x3C,4);
                    if(off+lfa+4<n&&!memcmp(inn+lfa,"PE\0\0",4))
                        DET(BP_MEDIUM,"Heuristic.Dropper.EmbeddedPE");
                }
            }
        }
        double e2=ent(b,n);
        if(e2>ENTROPY_PACKED){
            int ui=(HAS(b,n,"CreateWindowEx")||HAS(b,n,"MessageBoxW")||
                    HAS(b,n,"DialogBoxParam")||HAS(b,n,"RegisterClassEx"));
            if(!ui)DET(BP_PACKED,"Heuristic.PackedPE.Entropy%.2f",e2);
        }
    }

done:
    free(b); return ret;
}

const char *bp_get_threat_name(const char *p,int c){(void)p;(void)c;return g_name[0]?g_name:NULL;}
const char *bp_version(void){return "BytesProtector C Engine v3.0.0";}

#ifdef BP_STANDALONE
static const char *cs(int c){
    switch(c){case BP_EICAR:return "EICAR    ";case BP_CRITICAL:return "CRITICAL ";
              case BP_HIGH:return "HIGH     ";case BP_MEDIUM:return "MEDIUM   ";
              case BP_SUSPICIOUS:return "SUSPICIOUS";case BP_PACKED:return "PACKED   ";
              default:return "CLEAN    ";}
}
int main(int argc,char *argv[]){
    if(argc<2){fprintf(stderr,"usage: %s <file> [..]\n",argv[0]);return 1;}
    int any=0;
    for(int i=1;i<argc;i++){
        int r=bp_scan_file(argv[i]);
        printf("[%s] %s%s\n",cs(r),argv[i],r?bp_get_threat_name(argv[i],r):"");
        if(r)any=1;
    }
    return any?1:0;
}
#endif
