#pragma once
// The UI thread owns this state. Selection is consumed before dispatch, even
// when the callback fails to start, so STOP cannot silently repeat servicing.
namespace maintenance {
enum class MenuAction : unsigned { None=0, Install=1, Rollback=2 };
struct MenuState { MenuAction selected=MenuAction::None; };
typedef void (*MenuStart)(MenuAction,void*);
inline bool DispatchMenu(MenuState& state,unsigned command,MenuStart start,void* context) {
    if(state.selected!=MenuAction::None || !start || (command<1 || command>2))return false;
    state.selected=static_cast<MenuAction>(command);
    start(state.selected,context);
    return true;
}
}
