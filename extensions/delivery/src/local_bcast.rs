use libchat::DeliveryService;

type Callback = Box<dyn FnOnce(String, &Vec<u8>)>;

#[derive(Clone)]
struct LocalBroadcaster {
    subscribers: Arc<Mutex<HashMap<String, Vec<Callback>>>>,
}

impl LocalBroadcaster {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl DeliveryService for LocalBroadcaster {
    type Error = String;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error> {
        let callbacks = self
            .subscribers
            .lock()
            .unwrap()
            .remove(&envelope.delivery_address)
            .unwrap_or_default();

        for cb in callbacks {
            cb(envelope.delivery_address.clone(), &envelope.data);
        }

        Ok(())
    }

    fn subscribe<F>(&mut self, delivery_address: String, cb: F) -> Result<(), Self::Error>
    where
        F: FnOnce(String, &Vec<u8>) + 'static,
    {
        self.subscribers
            .lock()
            .unwrap()
            .entry(delivery_address)
            .or_default()
            .push(Box::new(cb));

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn local_bcast() {
        let ds = LocalBroadcast::new();
    }
}
