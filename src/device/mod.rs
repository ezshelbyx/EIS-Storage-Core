#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
    pub bus_path: String,
}
