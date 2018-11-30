# Arm64InspectiveC
Based on InspectiveC(https://github.com/DavidGoldman/InspectiveC). 
No theos/tweak/cycript env depend.

### Why this?
We just need a simple view for a small runtime logic sometimes.
So we just want to print the view on console and we can switch print/no any time.

### Different from the official
- Pure source code.
- No theos/tweak/cycript env depend.
- The result log will print on the console.

# Usage
- Import to your project.
- Add `-fno-objc-arc` for every `.m` files.
- Enjoy it. :)

```
#ifdef __arm64__
// init when start running
//        InspectiveC_Initialize();
if (InspectiveC_IsInitialize()) {
    InspectiveC_disableLogging();
    InspectiveC_watchSelector(@selector(sendEvent:));
    
    // You can create a button to switch enable/disable logging any time.
    //                InspectiveC_enableLogging();
}
#endif
```
