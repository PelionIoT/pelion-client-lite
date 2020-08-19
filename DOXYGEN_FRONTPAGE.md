## Device Management Client Lite API

This is the Doxygen-generated API documentation for Device Management Client Lite. See the [Files](files.html) section for documentation about a specific API. See also [Device Management documentation](https://www.pelion.com/docs/device-management/current/welcome/index.html).

Client Lite high-level APIs allow developers to create client side applications that connect to **Device Management**, with LwM2M features as described in the [Lightweight Machine to Machine Technical Specification](http://www.openmobilealliance.org/release/LightweightM2M/V1_0-20170208-A/OMA-TS-LightweightM2M-V1_0-20170208-A.pdf).

These APIs enable you to:

- Securely communicate with internet services over the industry standard TLS/DTLS.
- Manage devices.
- Fully control the endpoint and application logic from the service side.
- Provide functionality to update the devices over the air remotely controlled from the service side.

The API (C code) allows quick application development and portability.

## Running the Device Management client

Client Lite runs on top of event loop, originating from project called Nanostack. This event handler is sometimes referred as `ns_hal` and sometimes as `eventOS`, so any functions prefixed with those, are part of the same eventing system.
See \ref nanostack-eventloop for its API description.

To use the Client Lite, we must first create an event handler, by calling following function:

```c
int8_t eventOS_event_handler_create(void (*handler_func_ptr)(arm_event_t *), uint8_t init_event_type);
```

The `handler_func_ptr` is our callback function, and the return value of the call is our event handler's identifier. First parameter to our callback is event structure, that usually contain just some 8-bit type number to notify which event happened, but might carry other data as well. When creating the event handler, the event loop issues a call to the given function with type set to match `init_event_type`.

Now that the even loop is initialized, we may initialise the Client Lite and give our callbacks ID for it that we received from the event loop.

```c
pdmc_connect_init(my_event_id);
```

When the client is running, all the actions happen through events that are coming to our callback. The event handler that we gave for the client, might look like this:

```c
void pdmc_event_handler(arm_event_t *event)
{
    if (event->event_type == 0 && event->event_id == 0) {
        // Ignore the initial event.
        return;
    }

    if (event->event_id == LWM2M_INTERFACE_OBSERVER_EVENT_BOOTSTRAP_DONE) {
        printf("Client bootstrapped\n");
    } else if (event->event_id == M2M_CLIENT_EVENT_SETUP_COMPLETED) {
        pdmc_connect_register(get_network_interface());
    }
}
```

Final step for the application is then to start the even loop, which usually is just:
```c
eventOS_scheduler_run();
```

Please refer to [Device Management Client Lite Developer Guide](https://www.pelion.com/docs/pelion-client-lite/latest/developer-guide/index.html) for in depth tutorials how to use the client.
Also, see any of the given example applications for full OS specific applications. Code snippets in this page are simplified and uncomplete.
