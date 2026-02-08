//! ONNX model loading and inference via the `ort` crate.

use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use ndarray::Array4;
use ort::session::Session;
use ort::value::TensorRef;

pub struct Scanner {
    session: Mutex<Session>,
}

impl Scanner {
    /// Load an ONNX model from the given path.
    pub fn new(model_path: &Path) -> Result<Self> {
        let session = Session::builder()?
            .with_intra_threads(4)?
            .commit_from_file(model_path)?;

        Ok(Self {
            session: Mutex::new(session),
        })
    }

    /// Run inference on a single feature tensor.
    /// Input shape: (64, 3, 16, 16) -> reshaped to (1, 64, 3, 16, 16) for batch dim.
    /// Returns a maliciousness score in [0.0, 1.0].
    pub fn predict(&self, features: &Array4<f32>) -> Result<f32> {
        // Add batch dimension: (64,3,16,16) -> (1,64,3,16,16)
        let input = features
            .clone()
            .into_shape_with_order((1, 64, 3, 16, 16))?;

        let input_tensor = TensorRef::from_array_view(&input)?;

        let mut session = self
            .session
            .lock()
            .map_err(|e| anyhow::anyhow!("lock error: {e}"))?;
        let outputs = session.run(ort::inputs!["input" => input_tensor])?;

        let output_array = outputs["output"].try_extract_array::<f32>()?;
        let score = output_array.iter().next().copied().unwrap_or(0.0);

        Ok(score)
    }
}
