sudo ../target/debug/ViFuzz \
  --target /Users/gap_dev/fuzz_jack/Jackalope/build/examples/ImageIO/Release/test_imageio \
  --corpus-path ./corpus_discovered \
  --crashes-path ./crashes \
  --forks 7 \
  --fuzz-iterations 1000000 \
  -- -f @@
