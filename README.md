# Arm64InspectiveC
Based on InspectiveC.  https://github.com/DavidGoldman/InspectiveC

### Different from the official
- Directly import the source code into objective-c project.
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
