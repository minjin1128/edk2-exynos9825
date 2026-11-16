/* SPDX-License-Identifier: MIT
 * SEC72 framebuffer-only touch observation. No display-controller writes,
 * allocation, callback addresses, device strings, cache transitions or DMA.
 */
#include <N976nTouchCanvas.h>

#define CANVAS_W 1440U
#define CANVAS_H N976N_TOUCH_CANVAS_HEIGHT
#define BG 0x0010141CU
#define GRID 0x002C3748U
#define WHITE 0x00E8EEF8U
#define PRESS 0x00FFE040U
#define MOVE 0x0030E0FFU
#define RELEASE 0x00F060D8U
#define RADIUS 16U
#define FONT_SCALE 4U
#define FONT_W (6U * FONT_SCALE)
#define FONT_H (7U * FONT_SCALE)

typedef struct {
  N976N_PLATFORM_FB_INFO Info;
  BOOLEAN Ready, Ended, Marker, Hidden;
  UINTN X, Y;
  UINT64 Count, Action, Id, LastDrawTicks, LastSeenTicks;
} TOUCH_CANVAS_STATE;
STATIC TOUCH_CANVAS_STATE mCanvas;
STATIC BOOLEAN CanvasCpuReady (VOID);
STATIC VOID CanvasStore (UINTN Address, UINT32 Value);
STATIC VOID CanvasPublish (VOID);

/* Original small 5x7 diagnostic glyphs; each row is five low bits. */
STATIC CONST CHAR8 mGlyphKeys[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-:+.";
STATIC CONST UINT8 mGlyphs[][7] = {
 {14,17,17,31,17,17,17},{30,17,17,30,17,17,30},
 {14,17,16,16,16,17,14},{30,17,17,17,17,17,30},
 {31,16,16,30,16,16,31},{31,16,16,30,16,16,16},
 {14,17,16,23,17,17,15},{17,17,17,31,17,17,17},
 {14,4,4,4,4,4,14},{7,2,2,2,18,18,12},
 {17,18,20,24,20,18,17},{16,16,16,16,16,16,31},
 {17,27,21,21,17,17,17},{17,25,25,21,19,19,17},
 {14,17,17,17,17,17,14},{30,17,17,30,16,16,16},
 {14,17,17,17,21,18,13},{30,17,17,30,20,18,17},
 {15,16,16,14,1,1,30},{31,4,4,4,4,4,4},
 {17,17,17,17,17,17,14},{17,17,17,17,17,10,4},
 {17,17,17,21,21,27,17},{17,17,10,4,10,17,17},
 {17,17,10,4,4,4,4},{31,1,2,4,8,16,31},
 {14,17,19,21,25,17,14},{4,12,4,4,4,4,14},
 {14,17,1,2,4,8,31},{30,1,1,14,1,1,30},
 {2,6,10,18,31,2,2},{31,16,16,30,1,1,30},
 {14,16,16,30,17,17,14},{31,1,2,4,8,8,8},
 {14,17,17,14,17,17,14},{14,17,17,15,1,1,14},
 {1,2,2,4,8,8,16},{0,0,0,31,0,0,0},
 {0,4,4,0,4,4,0},{0,4,4,31,4,4,0},{0,0,0,0,0,12,12}
};
/* Inline character storage avoids absolute pointer relocations in .rdata.
 * The early SEC mapper deliberately relocates only writable PE data. */
typedef struct { UINTN X, Y; CHAR8 Text[48]; } CANVAS_LABEL;
STATIC CONST CANVAS_LABEL mLabels[] = {
 {48,32,"SEC72 TOUCH CANVAS - RAW PORTRAIT"},
 {48,76,"TAP 1 2 3 4 THEN DRAG AND RELEASE"},
 {48,120,"YELLOW PRESS / CYAN MOVE / MAGENTA RELEASE"},
 {48,164,"X INCREASES RIGHT / Y INCREASES DOWN"},
 {48,2008,"LOWER SCREEN RESERVED - MARKER OMITTED"},
 {180,400,"1"},{1320,400,"2"},{180,1750,"3"},{1320,1750,"4"},
 {1220,264,"X +"},{112,1920,"Y +"}
};
STATIC CONST UINTN mTargets[4][2] = {{150,410},{1290,410},{150,1760},{1290,1760}};
STATIC CONST CHAR8 mStateLines[][48] = {
  "WAIT FOR TOUCH NOW IN LOWER BAND", "PRESS", "MOVE", "RELEASE",
  "POINT BELOW CANVAS - NOT DRAWN", "OBSERVATION ENDED - SEE DIAGNOSTICS"
};

STATIC UINTN TextLength (CONST CHAR8 *Text)
{ UINTN N = 0; while (Text[N] != 0) N++; return N; }

STATIC BOOLEAN TextPixel (CONST CHAR8 *Text, UINTN X, UINTN Y)
{
  if (Y >= FONT_H || X / FONT_W >= TextLength (Text) ||
      (X % FONT_W) / FONT_SCALE >= 5) return FALSE;
  CHAR8 C = Text[X / FONT_W];
  for (UINTN I = 0; I < sizeof (mGlyphKeys) - 1; I++)
    if (mGlyphKeys[I] == C)
      return (mGlyphs[I][Y / FONT_SCALE] & (1U << (4 - (X % FONT_W) / FONT_SCALE))) != 0;
  return FALSE;
}

STATIC CONST CHAR8 *StateText (VOID)
{
  /* Selecting an integer row also prevents the optimizer from synthesizing
   * a read-only table of absolute pointers for the action-to-string branch. */
  UINTN Index = mCanvas.Action <= 3 ? (UINTN)mCanvas.Action : 0;
  if (mCanvas.Ended) Index = 5;
  else if (mCanvas.Hidden) Index = 4;
  return mStateLines[Index];
}

STATIC UINTN Distance (UINTN A, UINTN B) { return A > B ? A - B : B - A; }

STATIC UINT32 Background (UINTN X, UINTN Y)
{
  UINT32 Color = BG;
  if ((X == 720 && Y >= 320 && Y < 1984) ||
      (Y == 1085 && X >= 80 && X < 1360)) Color = GRID;
  if ((X >= 78 && X <= 82 && Y >= 320 && Y <= 1960) ||
      (Y >= 318 && Y <= 322 && X >= 80 && X <= 1360)) Color = WHITE;
  if ((X >= 1344 && X <= 1360 && Distance (Y,320) <= 1360-X) ||
      (Y >= 1944 && Y <= 1960 && Distance (X,80) <= 1960-Y)) Color = WHITE;
  for (UINTN I = 0; I < ARRAY_SIZE (mTargets); I++) {
    UINTN Dx = Distance (X, mTargets[I][0]), Dy = Distance (Y, mTargets[I][1]);
    if ((Dx >= 22 && Dx <= 25 && Dy <= 25) ||
        (Dy >= 22 && Dy <= 25 && Dx <= 25) || (Dx <= 1 && Dy <= 8) ||
        (Dy <= 1 && Dx <= 8)) Color = WHITE;
  }
  for (UINTN I = 0; I < ARRAY_SIZE (mLabels); I++) {
    CONST CANVAS_LABEL *L = &mLabels[I];
    if (X >= L->X && Y >= L->Y && TextPixel (L->Text, X-L->X, Y-L->Y)) Color = WHITE;
  }
  if (X >= 48 && Y >= 216 && TextPixel (StateText (), X-48, Y-216)) Color = WHITE;
  return Color;
}

STATIC VOID Pixel (UINTN X, UINTN Y, UINT32 Color)
{
  /* Even internal shape/erase helpers cannot enter the diagnostics or use a
   * device-supplied stride/base. Reserved bits preserve the admitted value. */
  if (X >= CANVAS_W || Y >= CANVAS_H) return;
  CanvasStore ((UINTN)mCanvas.Info.Base + Y * 5760U + X * 4U,
    (Color & 0xFFFFFFU) | ((UINT32)mCanvas.Info.ReservedByteValue << 24));
}

STATIC VOID Paint (UINTN X0, UINTN Y0, UINTN Width, UINTN Height)
{
  if (X0 >= CANVAS_W || Y0 >= CANVAS_H) return;
  if (Width > CANVAS_W-X0) Width = CANVAS_W-X0;
  if (Height > CANVAS_H-Y0) Height = CANVAS_H-Y0;
  for (UINTN Y = Y0; Y < Y0+Height; Y++)
    for (UINTN X = X0; X < X0+Width; X++) Pixel (X, Y, Background (X,Y));
}

STATIC VOID EraseMarker (VOID)
{
  if (!mCanvas.Marker) return;
  UINTN X = mCanvas.X > RADIUS ? mCanvas.X-RADIUS : 0;
  UINTN Y = mCanvas.Y > RADIUS ? mCanvas.Y-RADIUS : 0;
  Paint (X,Y,mCanvas.X+RADIUS+1-X,mCanvas.Y+RADIUS+1-Y);
  mCanvas.Marker = FALSE;
}

STATIC VOID DrawMarker (VOID)
{
  if (mCanvas.Hidden) return;
  UINT32 Color = mCanvas.Action == 1 ? PRESS : (mCanvas.Action == 2 ? MOVE : RELEASE);
  UINTN X0 = mCanvas.X > RADIUS ? mCanvas.X-RADIUS : 0;
  UINTN Y0 = mCanvas.Y > RADIUS ? mCanvas.Y-RADIUS : 0;
  for (UINTN Y = Y0; Y <= mCanvas.Y+RADIUS && Y < CANVAS_H; Y++) {
    for (UINTN X = X0; X <= mCanvas.X+RADIUS && X < CANVAS_W; X++) {
      UINTN Dx = Distance (X,mCanvas.X), Dy = Distance (Y,mCanvas.Y);
      UINTN Squared = Dx*Dx+Dy*Dy;
      if ((Squared >= 169 && Squared <= 256) ||
          (mCanvas.Action != 3 && ((Dx <= 1 && Dy <= 11) || (Dy <= 1 && Dx <= 11))))
        Pixel (X,Y,Color);
    }
  }
  mCanvas.Marker = TRUE;
}

STATIC BOOLEAN Disarm (VOID) { mCanvas.Ready = FALSE; return FALSE; }

STATIC VOID InitialPaint (VOID)
{
  /* The large initial fill performs no per-pixel font search. Reconstructing
   * the fixed background is needed only in these small decorations and in
   * later dirty rectangles. */
  for (UINTN Y = 0; Y < CANVAS_H; Y++)
    for (UINTN X = 0; X < CANVAS_W; X++) Pixel (X,Y,BG);
  Paint (720,320,1,1664); Paint (80,1085,1280,1);
  Paint (78,320,5,1641); Paint (80,318,1281,5);
  Paint (1344,304,17,33); Paint (64,1944,33,17);
  for (UINTN I = 0; I < ARRAY_SIZE (mTargets); I++)
    Paint (mTargets[I][0]-25,mTargets[I][1]-25,51,51);
  for (UINTN I = 0; I < ARRAY_SIZE (mLabels); I++)
    Paint (mLabels[I].X,mLabels[I].Y,TextLength (mLabels[I].Text)*FONT_W,FONT_H);
  Paint (48,216,1056,FONT_H);
}

STATIC BOOLEAN SessionValid (CONST N976N_TOUCH_SNAPSHOT *T)
{
  return T != NULL && T->Magic == N976N_TOUCH_SNAPSHOT_MAGIC && T->Version == 8 &&
    T->Size == sizeof (*T) && T->Profile == 0 && T->CounterHz == 26000000 &&
    T->Event.Mode == 1 && T->Event.WindowTicks == 20ULL * 26000000 &&
    T->Event.Polls <= TOUCH_EVENT_POLL_LIMIT &&
    T->Event.CoordinateCount <= T->Event.Polls &&
    T->Event.ElapsedTicks >= mCanvas.LastSeenTicks;
}

BOOLEAN EFIAPI N976nTouchCanvasBegin (CONST N976N_PLATFORM_FB_INFO *Info)
{
  mCanvas.Ready = FALSE;
  if (!CanvasCpuReady () || !N976nFbInfoValid (Info)) return FALSE;
  mCanvas = (TOUCH_CANVAS_STATE){0};
  mCanvas.Info = *Info; mCanvas.Ready = TRUE;
  /* One initial repaint only. Every contact update erases at most one 33x33
   * marker, redraws one and changes a single 1056x28 status line if needed. */
  InitialPaint ();
  CanvasPublish ();
  return TRUE;
}

BOOLEAN EFIAPI N976nTouchCanvasUpdate (CONST N976N_TOUCH_SNAPSHOT *T)
{
  if (!mCanvas.Ready || mCanvas.Ended || !CanvasCpuReady () ||
      !SessionValid (T)) return Disarm ();
  CONST N976N_TOUCH_EVENT_OBSERVATION *E = &T->Event;
  UINTN X, Y;
  if (E->Phase != 5 || E->Status != EFI_SUCCESS || E->Reason != 0 ||
      E->CoordinateCount == 0 || E->CoordinateCount < mCanvas.Count ||
      E->LastId < 1 || E->LastId > 10 || E->LastAction < 1 || E->LastAction > 3 ||
      (E->LastType != 0 && E->LastType != 3 && E->LastType != 5 && E->LastType != 6) ||
      !N976nTouchMapPoint (E->LastX,E->LastY,&X,&Y)) return Disarm ();
  CONST UINT8 *B = E->LastRaw;
  if ((B[0] & 3) != 0 || ((B[0] >> 2) & 15) != E->LastId ||
      (B[0] >> 6) != E->LastAction || ((UINTN)B[1]<<4 | B[3]>>4) != E->LastX ||
      ((UINTN)B[2]<<4 | (B[3]&15)) != E->LastY ||
      (UINT64)(((B[6]>>6)<<2) | (B[7]>>6)) != E->LastType) return Disarm ();
  mCanvas.LastSeenTicks = E->ElapsedTicks;
  if (E->CoordinateCount == mCanvas.Count) return TRUE;
  BOOLEAN Hidden = Y >= CANVAS_H;
  /* Only steady moves of the same contact/state may be coalesced. Press,
   * release, contact changes and entry/exit from the protected area are instant. */
  if (E->LastAction == 2 && mCanvas.Action == 2 && E->LastId == mCanvas.Id &&
      Hidden == mCanvas.Hidden && E->ElapsedTicks-mCanvas.LastDrawTicks < 1300000)
    return TRUE;
  BOOLEAN LabelChange = E->LastAction != mCanvas.Action || Hidden != mCanvas.Hidden;
  EraseMarker ();
  mCanvas.X = X; mCanvas.Y = Y; mCanvas.Hidden = Hidden;
  mCanvas.Action = E->LastAction; mCanvas.Id = E->LastId;
  mCanvas.Count = E->CoordinateCount; mCanvas.LastDrawTicks = E->ElapsedTicks;
  if (LabelChange) Paint (48,216,1056,FONT_H);
  DrawMarker ();
  CanvasPublish ();
  return TRUE;
}

BOOLEAN EFIAPI N976nTouchCanvasFinish (CONST N976N_TOUCH_SNAPSHOT *T)
{
  if (!mCanvas.Ready || mCanvas.Ended || !CanvasCpuReady () || !SessionValid (T) ||
      T->Event.Phase != 8) return Disarm ();
  /* Preserve the last observed press/move/release marker. Finishing the
   * bounded collection never invents a release event. */
  mCanvas.Ended = TRUE;
  Paint (48,216,1056,FONT_H);
  CanvasPublish ();
  return TRUE;
}

/* Native CPU/store boundary: component tests replace only this boundary,
 * retaining every production address calculation, gate and raster operation. */
STATIC BOOLEAN CanvasCpuReady (VOID)
{
  UINT64 El, Daif, Sctlr;
  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (El));
  __asm__ volatile ("mrs %0, daif" : "=r" (Daif));
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Sctlr));
  return El == 4 && (Daif & 0x3C0) == 0x3C0 &&
    !(Sctlr & (BIT0 | BIT2 | BIT12 | BIT25));
}
STATIC VOID CanvasStore (UINTN Address, UINT32 Value)
{ *(volatile UINT32 *)Address = Value; }
STATIC VOID CanvasPublish (VOID)
{ __asm__ volatile ("dsb sy" ::: "memory"); }
