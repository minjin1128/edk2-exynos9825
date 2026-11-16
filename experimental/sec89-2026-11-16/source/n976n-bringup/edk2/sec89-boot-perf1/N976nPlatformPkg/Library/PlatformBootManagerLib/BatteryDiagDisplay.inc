/* Frozen diagnostic records only; no MMIO, samples or policy actions. */
STATIC EFI_STATUS ShowBatteryDiagnostics(VOID)
{
 CONST volatile N976N_POWER_DIAG_REPORT *D=&mN976nPowerDiagReport;
 CONST volatile N976N_BATTERY_LIVE_REPORT *L=&mN976nBatteryLiveReport;
 CONST volatile N976N_BAT_BUS_REPORT *F=D->FirstFailure.Reason?&D->FirstFailure:&L->Capture;
 EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *O;UINTN Cols=0,Rows=0;EFI_STATUS S;
 if(!gST||!gST->ConOut||!gST->ConOut->Mode)return EFI_NOT_READY;
 O=gST->ConOut;
 if(O->Mode->MaxMode>1&&!EFI_ERROR(O->QueryMode(O,1,&Cols,&Rows))&&Cols==80&&Rows==50&&O->Mode->Mode!=1) {
   S=O->SetMode(O,1);if(EFI_ERROR(S))return S;
 }
 if(O->Mode->Mode<0||O->Mode->Mode>=O->Mode->MaxMode)return EFI_NOT_READY;
 S=O->QueryMode(O,O->Mode->Mode,&Cols,&Rows);if(EFI_ERROR(S))return S;
 if(Cols!=80||(Rows!=25&&Rows!=50))return EFI_UNSUPPORTED;
 S=O->ClearScreen(O);if(EFI_ERROR(S))return S;
 Print(L"SEC89 POWER DIAG1 / battery + charger read observation\r\n");
 Print(L"DIAG phase %Lx status %016Lx reason %Lx\r\n",D->Phase,D->Status,D->Reason);
 Print(L"LIVE phase %Lx status %016Lx reason %Lx published %Lx\r\n",L->Phase,L->Status,L->Reason,L->Published);
 Print(L"ACQUIRE %016Lx RELEASE %016Lx / samples %Lu complete %Lu\r\n",D->AcquireStatus,D->ReleaseStatus,D->Count,D->Complete);
 Print(L"RESTORED %Lx QUARANTINE %Lx / retired %Lx\r\n",D->Restored,D->Quarantine,D->Last.Retired);
 for(UINTN I=0;I<3;I++) {
   Print(L"#%u gauge %016Lx mask %03x / charger %016Lx mask %03x\r\n",(UINT32)I+1,D->GaugeStatus[I],D->Gauge[I].ValidMask,D->ChargeStatus[I],D->Charger[I].ValidMask);
   Print(L" SOC %u/1000 mV %u mA %d / value mask %03x\r\n",D->Values[I].SocPermille,D->Values[I].VoltageMv,D->Values[I].CurrentMa,D->Values[I].ValueValidMask);
   Print(L" RAW B2 B3 B4 B7 B8 B9 BA BB BD C0 C3: ");
   for(UINTN J=0;J<N976N_PWR_COUNT;J++)Print(L"%02x ",(UINT32)D->Charger[I].Byte[J]);
   Print(L"\r\n");
   if(Rows==50)Print(L" seq %Lu ticks %Lu..%Lu / 26000000 Hz\r\n",D->Charger[I].Sequence,D->Begin[I],D->End[I]);
 }
 Print(L"FIRST reason %Lx phase %Lx field %Lx register %Lx\r\n",F->Reason,F->FailurePhase,F->Field,F->Register);
 Print(L"COMPARE at %08x expected %016Lx actual %016Lx\r\n",(UINT32)F->FirstAddress,F->FirstExpected,F->FirstActual);
 if(Rows==50) {
   Print(L"MASK %016Lx valid %Lx kind %Lx\r\n",F->FirstMask,F->CaptureValid,F->FirstCompare);
   Print(L"FIRST IRQ/TRANS/FIFO/AUTO %08x/%08x/%08x/%08x\r\n",(UINT32)F->FirstInterrupt,(UINT32)F->FirstTransfer,(UINT32)F->FirstFifo,(UINT32)F->FirstAuto);
   Print(L"LAST xfers/TX/RX %Lu/%Lu/%Lu wait %Lu exit %Lx\r\n",D->Last.Transfers,D->Last.TxBytes,D->Last.RxBytes,D->Last.WaitUs,D->Last.WaitExit);
   Print(L"ACQUIRE MODE/QCH/CTL/USI %08x/%08x/%08x/%08x\r\n",(UINT32)D->Acquire.InheritedMode,(UINT32)D->Acquire.InheritedQch,(UINT32)D->Acquire.InheritedControl,(UINT32)D->Acquire.InheritedUsiControl);
   Print(L"PIN changed/restored %Lx/%Lx; clock %Lu Hz\r\n",D->Last.PinChangedMask,D->Last.PinRestoredMask,D->Last.InputHz);
   Print(L"UFS restore %Lx Q %Lx; Windows load/start %Lu/%Lu\r\n",mN976nUfsReport.Restore,mN976nUfsReport.Quarantined,mN976nWindowsReport.LoadCount,mN976nWindowsReport.StartCount);
 }
 Print(L"Frozen reads. ANY bytes without a valid mask are NOT values.\r\n");
 Print(L"No charger setting/WDT writes; no Windows or storage writes.\r\n");
 Print(L"Unplug USB/charger. 120s / VolumeDown: guarded shutdown request.\r\n");
 return EFI_SUCCESS;
}
