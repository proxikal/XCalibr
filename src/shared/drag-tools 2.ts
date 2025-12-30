export type AutoScrollInput = {
  clientY: number;
  rectTop: number;
  rectBottom: number;
  threshold: number;
  speed: number;
};

export const getAutoScrollDelta = ({
  clientY,
  rectTop,
  rectBottom,
  threshold,
  speed
}: AutoScrollInput) => {
  if (clientY < rectTop + threshold) return -speed;
  if (clientY > rectBottom - threshold) return speed;
  return 0;
};
