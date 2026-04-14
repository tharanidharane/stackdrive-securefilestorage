import { useState, useEffect, useCallback, useRef } from 'react';

const PIPELINE_STAGES = [
  { name: 'Hash Check', icon: 'Fingerprint', detail: 'Comparing against known malware signatures' },
  { name: 'ZIP Validation', icon: 'Archive', detail: 'Verifying archive structure & integrity' },
  { name: 'ClamAV Scan', icon: 'Bug', detail: 'Antivirus engine deep scan' },
  { name: 'Sandbox Analysis', icon: 'Box', detail: 'Docker isolated behavior analysis' },
  { name: 'Encryption', icon: 'Lock', detail: 'AES-256 + Kyber PQ encryption' },
];

export function usePipelineSimulation() {
  const [isActive, setIsActive] = useState(false);
  const [fileName, setFileName] = useState('');
  const [stages, setStages] = useState([]);
  const [result, setResult] = useState(null); // 'safe' | 'blocked' | null
  const [showBanner, setShowBanner] = useState(false);
  const timeoutRef = useRef([]);

  const clearTimeouts = () => {
    timeoutRef.current.forEach(t => clearTimeout(t));
    timeoutRef.current = [];
  };

  const startPipeline = useCallback((name, shouldFail = false, failAtStage = -1) => {
    clearTimeouts();
    setIsActive(true);
    setFileName(name);
    setResult(null);
    setShowBanner(false);

    // Initialize all stages as pending
    const initialStages = PIPELINE_STAGES.map(s => ({
      ...s,
      status: 'pending',
      statusDetail: 'Pending',
    }));
    setStages(initialStages);

    // Simulate each stage progressing
    PIPELINE_STAGES.forEach((stage, index) => {
      // Start running
      const startDelay = index * 2500 + 500;
      const t1 = setTimeout(() => {
        setStages(prev => prev.map((s, i) => 
          i === index ? { ...s, status: 'running', statusDetail: stage.detail } : s
        ));
      }, startDelay);
      timeoutRef.current.push(t1);

      // Complete
      const endDelay = startDelay + 2000;
      const t2 = setTimeout(() => {
        const isFailed = shouldFail && index === failAtStage;
        setStages(prev => prev.map((s, i) => {
          if (i === index) {
            return {
              ...s,
              status: isFailed ? 'fail' : 'pass',
              statusDetail: isFailed ? 'Threat detected!' : `${stage.name} passed`,
            };
          }
          // If this stage failed, mark remaining as skipped
          if (isFailed && i > index) {
            return { ...s, status: 'skipped', statusDetail: 'Skipped — prior layer failed' };
          }
          return s;
        }));

        // If failed, show result
        if (isFailed) {
          const t3 = setTimeout(() => {
            setResult('blocked');
            setShowBanner(true);
            const t4 = setTimeout(() => setShowBanner(false), 4000);
            timeoutRef.current.push(t4);
          }, 500);
          timeoutRef.current.push(t3);
        }

        // If last stage completed successfully
        if (!shouldFail && index === PIPELINE_STAGES.length - 1) {
          const t3 = setTimeout(() => {
            setResult('safe');
            setShowBanner(true);
            const t4 = setTimeout(() => setShowBanner(false), 4000);
            timeoutRef.current.push(t4);
          }, 500);
          timeoutRef.current.push(t3);
        }
      }, endDelay);
      timeoutRef.current.push(t2);

      // Stop processing if we'll fail at this stage
      if (shouldFail && index === failAtStage) return;
    });
  }, []);

  const resetPipeline = useCallback(() => {
    clearTimeouts();
    setIsActive(false);
    setFileName('');
    setStages([]);
    setResult(null);
    setShowBanner(false);
  }, []);

  useEffect(() => {
    return () => clearTimeouts();
  }, []);

  return {
    isActive,
    fileName,
    stages,
    result,
    showBanner,
    startPipeline,
    resetPipeline,
  };
}
